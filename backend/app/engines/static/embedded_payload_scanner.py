"""
Embedded Payload Scanner — static child/dropper APK detection.

Droppers (e.g. "Wedding Invitation" SMS stealers, fake mParivahan/RTO challan apps)
ship the real malware as a child APK hidden inside the parent — usually under
assets/ or res/raw/, often renamed (.png, .jpg, .dat, no extension) and sometimes
XOR/AES-encrypted. The child is only installed after user interaction, so the
dynamic sandbox frequently never sees it. This scanner inspects every ZIP entry
by its *content* (magic bytes), not its name, and recurses into nested archives.
"""

import io
import math
import zipfile
import hashlib
import logging
from typing import Dict, Any, List, Tuple

logger = logging.getLogger(__name__)

MAX_ENTRY_BYTES = 200 * 1024 * 1024
MAX_DEPTH = 3
ENTROPY_MIN_SIZE = 64 * 1024

_MEDIA_EXT = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".mp3", ".mp4", ".ogg", ".ttf", ".otf", ".woff")

# Code-level hints that the app installs another package
INSTALL_STRINGS = [
    b"application/vnd.android.package-archive",
    b"android.intent.action.INSTALL_PACKAGE",
    b"PackageInstaller$Session",
    b"Landroid/content/pm/PackageInstaller",
    b"REQUEST_INSTALL_PACKAGES",
    b"canRequestPackageInstalls",
    b"MANAGE_UNKNOWN_APP_SOURCES",
]


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def _sanitize_zip(raw: bytes) -> Tuple[bytes, int]:
    """
    Clear the 'encrypted' general-purpose flag in every local and central
    directory header. Android's installer ignores this bit, so malware sets it
    to make Python/JADX/apktool refuse to extract entries (fake encryption).
    Also rewrites invalid compression methods to STORED — Android treats any
    method other than DEFLATE as stored, another common tampering trick.
    Returns (patched_bytes, number_of_header_fields_patched).
    """
    buf = bytearray(raw)
    patched = 0
    for sig, off in ((b"PK", 6), (b"PK", 8)):
        i = buf.find(sig)
        while i != -1 and i + off + 4 <= len(buf):
            if buf[i + off] & 0x01:
                buf[i + off] &= 0xFE
                patched += 1
            method = buf[i + off + 2] | (buf[i + off + 3] << 8)
            if method not in (0, 8):
                buf[i + off + 2] = buf[i + off + 3] = 0
                patched += 1
            i = buf.find(sig, i + 4)
    return bytes(buf), patched


def _classify(data: bytes) -> str:
    if data[:4] == b"PK\x03\x04":
        return "zip"
    if data[:4] == b"dex\n":
        return "dex"
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:3] == b"\x1f\x8b\x08":
        return "gzip"
    return ""


def _inspect_nested_zip(data: bytes) -> Dict[str, Any]:
    """Return info about a nested zip; is_apk if it contains a manifest + dex."""
    info = {"is_apk": False, "package_name": None, "entries": 0}
    try:
        with zipfile.ZipFile(io.BytesIO(_sanitize_zip(data)[0])) as z:
            names = z.namelist()
            info["entries"] = len(names)
            info["is_apk"] = "AndroidManifest.xml" in names and any(
                n.startswith("classes") and n.endswith(".dex") for n in names
            )
            if info["is_apk"]:
                try:
                    from androguard.core.apk import APK  # androguard >= 4
                except ImportError:
                    try:
                        from androguard.core.bytecodes.apk import APK
                    except ImportError:
                        APK = None
                if APK:
                    try:
                        a = APK(_sanitize_zip(data)[0], raw=True)
                        info["package_name"] = a.get_package()
                        info["permissions"] = sorted(a.get_permissions())
                    except Exception as e:
                        logger.debug(f"androguard could not parse nested APK: {e}")
    except zipfile.BadZipFile:
        pass
    return info


def _scan_zip(zf: zipfile.ZipFile, prefix: str, depth: int, out: Dict[str, Any]) -> None:
    for entry in zf.infolist():
        name = entry.filename
        full = f"{prefix}{name}"
        if entry.is_dir() or entry.file_size == 0 or entry.file_size > MAX_ENTRY_BYTES:
            continue
        lower = name.lower()
        is_primary_dex = depth == 0 and "/" not in name and lower.startswith("classes") and lower.endswith(".dex")
        is_lib = depth == 0 and lower.startswith("lib/") and lower.endswith(".so")
        try:
            data = zf.read(entry)
        except Exception as e:
            out["unreadable_entries"].append({"path": full, "error": str(e)[:120]})
            continue

        if depth == 0 and (lower.endswith(".dex") or is_primary_dex):
            for s in INSTALL_STRINGS:
                if s in data and s.decode() not in out["install_indicators"]:
                    out["install_indicators"].append(s.decode())
        if is_primary_dex or is_lib:
            continue

        kind = _classify(data)
        sha = hashlib.sha256(data).hexdigest()
        disguised = lower.endswith(_MEDIA_EXT) or "." not in name.rsplit("/", 1)[-1]

        if kind == "zip":
            nested = _inspect_nested_zip(data)
            if nested["is_apk"]:
                out["embedded_apks"].append({
                    "path": full, "size": len(data), "sha256": sha,
                    "package_name": nested.get("package_name"),
                    "permissions": nested.get("permissions", []),
                    "disguised": disguised or not lower.endswith(".apk"),
                })
            if depth < MAX_DEPTH:
                try:
                    with zipfile.ZipFile(io.BytesIO(_sanitize_zip(data)[0])) as nz:
                        _scan_zip(nz, full + "!/", depth + 1, out)
                except zipfile.BadZipFile:
                    pass
        elif kind == "dex":
            out["embedded_dex"].append({"path": full, "size": len(data), "sha256": sha, "disguised": disguised})
        elif kind == "elf" and not lower.startswith("lib/"):
            out["hidden_elf"].append({"path": full, "size": len(data), "sha256": sha})
        elif (
            lower.startswith(("assets/", "res/raw/"))
            and len(data) >= ENTROPY_MIN_SIZE
            and not lower.endswith(_MEDIA_EXT + (".zip", ".gz", ".jar", ".bin", ".tflite", ".pak"))
        ):
            ent = _entropy(data[: 1024 * 1024])
            if ent > 7.9:
                out["encrypted_blobs"].append({
                    "path": full, "size": len(data), "sha256": sha, "entropy": round(ent, 3),
                })
        elif lower.endswith(".apk"):
            # Named .apk but not a valid zip -> likely encrypted payload
            out["encrypted_blobs"].append({"path": full, "size": len(data), "sha256": sha, "entropy": round(_entropy(data[:1024 * 1024]), 3)})


def scan_apk(apk_path: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "embedded_apks": [],
        "embedded_dex": [],
        "hidden_elf": [],
        "encrypted_blobs": [],
        "install_indicators": [],
        "unreadable_entries": [],
        "zip_tampering": 0,
    }
    try:
        with open(apk_path, "rb") as fh:
            raw, out["zip_tampering"] = _sanitize_zip(fh.read())
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            _scan_zip(zf, "", 0, out)
    except Exception as e:
        out["error"] = str(e)

    # Install capability + an encrypted asset is the classic encrypted-dropper pattern
    can_install = bool(out["install_indicators"])
    # Fake-encrypted ZIP headers are anti-analysis tampering never seen in legit apps;
    # combined with any hidden payload it is a dropper.
    tampered = out["zip_tampering"] > 0
    out["is_dropper"] = bool(out["embedded_apks"]) or (
        (can_install or tampered) and bool(out["embedded_dex"] or out["encrypted_blobs"])
    )
    out["summary"] = (
        f"{len(out['embedded_apks'])} embedded APK(s), {len(out['embedded_dex'])} hidden DEX, "
        f"{len(out['encrypted_blobs'])} encrypted blob(s), install-capable={can_install}, zip-tampering={out['zip_tampering']} headers"
    )
    logger.info(f"Embedded payload scan: {out['summary']}")
    return out
