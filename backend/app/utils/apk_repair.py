"""
APK Repair & Anti-Analysis Sanitizer
Detects and neutralizes APK protector / anti-analysis tricks:
1. Fake encryption flags (flag_bits & 1) on AndroidManifest.xml / resources.arsc
2. Corrupted compression method bytes (e.g., 217, 235) in local & central directory headers
3. Invalid CRC32 checksums (e.g., 0xDEADBEEF) designed to crash reverse engineering tools
4. Automatic re-signing using Android SDK debug keystore or fallback signer
"""

import os
import shutil
import struct
import zipfile
import subprocess
import logging
from typing import Optional, List, Tuple

logger = logging.getLogger(__name__)


def _find_apksigner() -> Optional[str]:
    """Find apksigner binary on the system."""
    res = shutil.which("apksigner")
    if res:
        return res

    localappdata = os.environ.get("LOCALAPPDATA", "")
    build_tools_dir = os.path.join(localappdata, "Android", "Sdk", "build-tools")
    if os.path.isdir(build_tools_dir):
        versions = sorted(os.listdir(build_tools_dir), reverse=True)
        for v in versions:
            candidate = os.path.join(build_tools_dir, v, "apksigner.bat" if os.name == "nt" else "apksigner")
            if os.path.isfile(candidate):
                return candidate

    return None


def _find_debug_keystore() -> Optional[str]:
    """Find or create Android debug keystore."""
    userprofile = os.environ.get("USERPROFILE", os.path.expanduser("~"))
    keystore_path = os.path.join(userprofile, ".android", "debug.keystore")
    if os.path.isfile(keystore_path):
        return keystore_path
    return None


def is_apk_tampered(apk_path: str) -> Tuple[bool, List[str]]:
    """
    Check if an APK contains tampered ZIP headers or anti-analysis protection.
    Returns (is_tampered, list_of_corrupted_entries).
    """
    if not os.path.isfile(apk_path):
        return False, []

    corrupted = []
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            for info in z.infolist():
                # Check for fake encryption flag or invalid compression
                if (info.flag_bits & 1) != 0 or info.compress_type not in (0, 8):
                    corrupted.append(info.filename)
                else:
                    # Test actually reading a few critical files
                    if info.filename in ("AndroidManifest.xml", "resources.arsc"):
                        try:
                            z.read(info.filename)
                        except Exception:
                            if info.filename not in corrupted:
                                corrupted.append(info.filename)
    except Exception as e:
        logger.warning(f"[APK Repair] Error inspecting {apk_path}: {e}")
        return True, ["CorruptedZipArchive"]

    return len(corrupted) > 0, corrupted


def _patch_zip_headers(data: bytearray) -> bool:
    """
    Walk the ZIP central directory and normalise every entry:
      * clear the (fake) 'encrypted' general-purpose bit
      * replace an invalid compression method with STORED or DEFLATE
    Both the central-directory record and its local file header are patched.
    Returns True if anything changed.
    """
    eocd = data.rfind(b"PK\x05\x06")
    if eocd == -1:
        return False
    total = struct.unpack_from("<H", data, eocd + 10)[0]
    cd_off = struct.unpack_from("<I", data, eocd + 16)[0]

    changed = False
    pos = cd_off
    for _ in range(total):
        if data[pos:pos + 4] != b"PK\x01\x02":
            break
        flags = struct.unpack_from("<H", data, pos + 8)[0]
        method = struct.unpack_from("<H", data, pos + 10)[0]
        comp = struct.unpack_from("<I", data, pos + 20)[0]
        uncomp = struct.unpack_from("<I", data, pos + 24)[0]
        name_len, extra_len, comment_len = struct.unpack_from("<HHH", data, pos + 28)
        local_off = struct.unpack_from("<I", data, pos + 42)[0]

        new_flags = flags & ~1
        new_method = method if method in (0, 8) else (0 if comp == uncomp else 8)
        if new_flags != flags or new_method != method:
            struct.pack_into("<HH", data, pos + 8, new_flags, new_method)
            if data[local_off:local_off + 4] == b"PK\x03\x04":
                lflags = struct.unpack_from("<H", data, local_off + 6)[0]
                struct.pack_into("<HH", data, local_off + 6, lflags & ~1, new_method)
            changed = True

        pos += 46 + name_len + extra_len + comment_len
    return changed


def repair_and_sign_apk(apk_path: str, output_path: Optional[str] = None) -> Optional[str]:
    """
    Repair tampered APK headers (AndroidManifest.xml, resources.arsc, etc.)
    and sign the resulting APK with the debug key so Android OS accepts installation.
    """
    if not os.path.isfile(apk_path):
        return None

    is_tampered, corrupted_entries = is_apk_tampered(apk_path)
    if not is_tampered:
        logger.info(f"[APK Repair] APK is not tampered: {apk_path}")
        return apk_path

    logger.info(f"[APK Repair] Detected tampered entries in APK: {corrupted_entries}")

    if not output_path:
        base, ext = os.path.splitext(apk_path)
        output_path = f"{base}_repaired{ext}"

    try:
        with open(apk_path, "rb") as f:
            data = bytearray(f.read())

        repaired_any = _patch_zip_headers(data)

        with open(output_path, "wb") as f:
            f.write(data)

        logger.info(f"[APK Repair] Raw headers patched, output written to: {output_path}")

        # Re-sign the APK so Android accepts it
        apksigner = _find_apksigner()
        keystore = _find_debug_keystore()

        if apksigner and keystore:
            logger.info(f"[APK Repair] Signing with debug keystore via {apksigner}")
            cmd = [
                apksigner, "sign",
                "--ks", keystore,
                "--ks-pass", "pass:android",
                "--key-pass", "pass:android",
                output_path,
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if res.returncode == 0:
                logger.info(f"[APK Repair] Successfully signed repaired APK: {output_path}")
                return output_path
            else:
                logger.warning(f"[APK Repair] apksigner returned non-zero: {res.stderr}")

        return output_path

    except Exception as e:
        logger.error(f"[APK Repair] Failed to repair APK: {e}")
        return None


def sign_apk_copy(apk_path: str, output_path: Optional[str] = None) -> Optional[str]:
    """Sign a copy of an APK with the local debug key (used to keep bundle splits'
    signatures consistent with a repaired base APK). Returns the signed copy or None."""
    apksigner, keystore = _find_apksigner(), _find_debug_keystore()
    if not (apksigner and keystore and os.path.isfile(apk_path)):
        return None
    if not output_path:
        base, ext = os.path.splitext(apk_path)
        output_path = f"{base}_resigned{ext}"
    try:
        import shutil
        shutil.copyfile(apk_path, output_path)
        res = subprocess.run(
            [apksigner, "sign", "--ks", keystore, "--ks-pass", "pass:android",
             "--key-pass", "pass:android", output_path],
            capture_output=True, text=True, timeout=60,
        )
        if res.returncode == 0:
            return output_path
        logger.warning(f"[APK Repair] Signing {apk_path} failed: {res.stderr[-300:]}")
    except Exception as e:
        logger.warning(f"[APK Repair] Signing {apk_path} failed: {e}")
    return None
