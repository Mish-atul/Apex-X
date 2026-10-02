import os
import zipfile
import shutil
from fastapi import UploadFile

def is_valid_apk(file_path: str) -> bool:
    """
    Validates if the file is a proper ZIP archive and contains essential APK files.
    Also handles anti-analysis tampered APKs that contain AndroidManifest.xml.
    """
    if not os.path.isfile(file_path):
        return False

    if not zipfile.is_zipfile(file_path):
        # Check if it has tampered APK headers
        try:
            from app.utils.apk_repair import is_apk_tampered
            tampered, _ = is_apk_tampered(file_path)
            return tampered
        except Exception:
            return False
        
    try:
        with zipfile.ZipFile(file_path, 'r') as z:
            file_names = z.namelist()
            if "AndroidManifest.xml" in file_names:
                return True
    except Exception:
        pass

    # Fallback to checking tamper detection
    try:
        from app.utils.apk_repair import is_apk_tampered
        tampered, _ = is_apk_tampered(file_path)
        return tampered
    except Exception:
        return False

def save_upload_file(upload_file: UploadFile, destination_path: str) -> bool:
    """
    Saves an uploaded file to the local disk safely in chunks.
    """
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(destination_path), exist_ok=True)
        
        with open(destination_path, "wb") as buffer:
            shutil.copyfileobj(upload_file.file, buffer)
        
        # Reset file pointer for any further reading (like hashing)
        upload_file.file.seek(0)
        return True
    except Exception as e:
        print(f"Error saving file: {e}")
        return False


def long_path(path: str) -> str:
    """Return a Windows extended-length path so deep decompiled trees (> MAX_PATH) can be read."""
    if os.name != "nt" or not path or path.startswith("\\\\?\\"):
        return path
    return "\\\\?\\" + os.path.abspath(path)


# ---------------------------------------------------------------------------
# Split-APK bundle support (.xapk / .apks / .apkm)
# ---------------------------------------------------------------------------
import json
import logging as _logging

_log = _logging.getLogger(__name__)

APK_EXTENSIONS = (".apk",)
BUNDLE_EXTENSIONS = (".xapk", ".apks", ".apkm")
ALLOWED_UPLOAD_EXTENSIONS = APK_EXTENSIONS + BUNDLE_EXTENSIONS
BUNDLE_DIRNAME = "bundle"
BUNDLE_INFO_FILE = "splits.json"
MAX_BUNDLE_UNCOMPRESSED = 4 * 1024 * 1024 * 1024  # 4 GiB zip-bomb guard


def is_bundle_filename(filename: str) -> bool:
    return bool(filename) and filename.lower().endswith(BUNDLE_EXTENSIONS)


def is_allowed_upload(filename: str) -> bool:
    return bool(filename) and filename.lower().endswith(ALLOWED_UPLOAD_EXTENSIONS)


def _manifest_split_attr(apk_path: str):
    """Return (package, split_name or None). Raises if manifest unreadable."""
    from androguard.core.apk import APK  # type: ignore
    apk = APK(apk_path)
    split = None
    try:
        split = apk.get_attribute_value("manifest", "split")
    except Exception:
        try:
            split = apk.get_android_manifest_xml().get("split")
        except Exception:
            split = None
    return apk.get_package(), (split or None)


def is_valid_bundle(file_path: str) -> bool:
    """A bundle is a ZIP containing at least one .apk entry."""
    if not os.path.isfile(file_path) or not zipfile.is_zipfile(file_path):
        return False
    try:
        with zipfile.ZipFile(file_path) as z:
            return any(n.lower().endswith(".apk") for n in z.namelist())
    except Exception:
        return False


def extract_bundle(bundle_path: str, case_dir: str) -> dict:
    """Extract a split-APK bundle into <case_dir>/bundle/ and identify the base APK.

    Writes and returns bundle info: {bundle_file, format, base_apk, splits[], package_name}.
    Paths in the info are relative to case_dir. Raises ValueError on invalid bundles.
    """
    out_dir = os.path.join(case_dir, BUNDLE_DIRNAME)
    os.makedirs(out_dir, exist_ok=True)
    out_real = os.path.realpath(out_dir)

    with zipfile.ZipFile(bundle_path) as z:
        total = sum(i.file_size for i in z.infolist())
        if total > MAX_BUNDLE_UNCOMPRESSED:
            raise ValueError("Bundle too large when uncompressed")
        for info in z.infolist():
            target = os.path.realpath(os.path.join(out_dir, info.filename))
            if not (target == out_real or target.startswith(out_real + os.sep)):
                raise ValueError(f"Unsafe path in bundle: {info.filename}")
        z.extractall(out_dir)

    apks = []
    for root, _dirs, files in os.walk(out_dir):
        for f in files:
            if f.lower().endswith(".apk"):
                apks.append(os.path.join(root, f))
    if not apks:
        raise ValueError("Bundle contains no APK files")

    base, package, splits = None, None, []
    for p in sorted(apks):
        try:
            pkg, split = _manifest_split_attr(p)
        except Exception as e:
            _log.warning(f"Could not parse manifest of {p}: {e}")
            pkg, split = None, "unknown"
        if split is None and base is None:
            base, package = p, pkg
        else:
            splits.append(p)

    if base is None:
        # .xapk: manifest.json lists split_apks with id "base"
        mj = os.path.join(out_dir, "manifest.json")
        if os.path.isfile(mj):
            try:
                with open(mj, encoding="utf-8") as fh:
                    meta = json.load(fh)
                package = package or meta.get("package_name")
                for e in meta.get("split_apks", []):
                    if e.get("id") == "base":
                        cand = os.path.join(out_dir, e.get("file", ""))
                        if os.path.isfile(cand):
                            base = cand
                            break
            except Exception:
                pass
    if base is None:
        # Fallback on naming conventions
        for p in apks:
            if os.path.basename(p).lower() in ("base.apk", "base-master.apk"):
                base = p
                break
    if base is None:
        if len(apks) == 1:
            base = apks[0]
        else:
            raise ValueError("Could not identify base APK in bundle")
    splits = [p for p in apks if p != base]

    rel = lambda p: os.path.relpath(p, case_dir).replace("\\", "/")
    info = {
        "bundle_file": os.path.basename(bundle_path),
        "format": os.path.splitext(bundle_path)[1].lower().lstrip("."),
        "base_apk": rel(base),
        "splits": sorted(rel(p) for p in splits),
        "package_name": package,
    }
    with open(os.path.join(out_dir, BUNDLE_INFO_FILE), "w", encoding="utf-8") as fh:
        json.dump(info, fh, indent=2)
    return info


def load_bundle_info(case_dir: str):
    path = os.path.join(case_dir, BUNDLE_DIRNAME, BUNDLE_INFO_FILE)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def resolve_analysis_apk(case_dir: str, apk_name: str) -> str:
    """Path of the APK to analyse: the base APK for bundles, the file itself otherwise.
    Extracts the bundle lazily if it has not been extracted yet."""
    path = os.path.join(case_dir, apk_name)
    if not is_bundle_filename(apk_name):
        return path
    info = load_bundle_info(case_dir)
    if info is None and os.path.isfile(path):
        info = extract_bundle(path, case_dir)
    if not info:
        return path
    return os.path.join(case_dir, info["base_apk"])


def get_split_apks(apk_path: str) -> list:
    """If apk_path is the base APK of an extracted bundle, return absolute paths of its splits."""
    d = os.path.dirname(os.path.abspath(apk_path))
    while True:
        if os.path.basename(d) == BUNDLE_DIRNAME:
            case_dir = os.path.dirname(d)
            info = load_bundle_info(case_dir)
            if info and os.path.normcase(os.path.abspath(os.path.join(case_dir, info["base_apk"]))) == os.path.normcase(os.path.abspath(apk_path)):
                return [os.path.join(case_dir, s) for s in info.get("splits", [])]
            return []
        parent = os.path.dirname(d)
        if parent == d:
            return []
        d = parent
