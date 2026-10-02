"""
APKTool Wrapper — Real Integration
Decompiles APK files into Smali code, resources, and AndroidManifest.xml
using the apktool command-line tool via subprocess.
"""

from app.utils.file_utils import long_path
import os
import subprocess
import shutil
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

# Timeout for apktool decompilation (seconds)
APKTOOL_TIMEOUT = int(os.environ.get("APEX_APKTOOL_TIMEOUT", "600"))


def _find_apktool() -> Optional[str]:
    """Check if apktool is available on the system PATH or in local tools dir."""
    result = shutil.which("apktool")
    if result:
        return result
    # Check local tools directory (project_root/tools/)
    backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
    tools_dir = os.path.join(os.path.dirname(backend_dir), "tools")
    local_jar = os.path.join(tools_dir, "apktool.jar")
    if os.path.isfile(local_jar):
        return local_jar
    local_bat = os.path.join(tools_dir, "apktool.bat")
    if os.path.isfile(local_bat):
        return local_bat
    # Common installation paths
    for path in ["/usr/local/bin/apktool", "/usr/bin/apktool", "/opt/homebrew/bin/apktool"]:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def decompile_apk(apk_path: str, output_dir: str, force: bool = True) -> Optional[str]:
    """
    Decompile an APK file using APKTool.

    Args:
        apk_path: Absolute path to the APK file.
        output_dir: Directory where decompiled output will be written.
        force: If True, overwrite existing output directory.

    Returns:
        Path to decompiled output directory, or None on failure.
    """
    if not os.path.exists(apk_path):
        logger.error(f"APK file not found: {apk_path}")
        return None

    apktool_bin = _find_apktool()
    if not apktool_bin:
        logger.warning(
            "apktool binary not found on system PATH. "
            "Install it: https://ibotpeaches.github.io/Apktool/install/"
        )
        return None

    base = ["java", "-jar", apktool_bin] if apktool_bin.endswith(".jar") else [apktool_bin]

    # Attempt 1: full decode. Attempt 2: skip resource decoding (-r), which avoids
    # most resource-table failures on obfuscated/large apps and is much faster.
    attempts = [
        ("full", base + ["d", apk_path, "-o", output_dir] + (["-f"] if force else [])),
        ("no-resources", base + ["d", "-r", apk_path, "-o", output_dir, "-f"]),
    ]
    for label, cmd in attempts:
        logger.info(f"Running APKTool ({label}): {' '.join(cmd)}")
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=APKTOOL_TIMEOUT,
                cwd=os.path.dirname(apk_path),
            )
            if result.returncode == 0:
                if not os.path.exists(os.path.join(output_dir, "AndroidManifest.xml")):
                    logger.warning("APKTool output missing AndroidManifest.xml")
                logger.info(f"APKTool decompilation successful ({label}): {output_dir}")
                return output_dir
            logger.warning(f"APKTool {label} failed (exit {result.returncode}): {result.stderr[-500:]}")
        except subprocess.TimeoutExpired:
            logger.warning(f"APKTool {label} timed out after {APKTOOL_TIMEOUT}s for: {apk_path}")
        except FileNotFoundError:
            logger.error("APKTool binary disappeared or is not executable")
            return None
        except Exception as e:
            logger.warning(f"APKTool {label} unexpected error: {e}")
    logger.error(f"APKTool failed on all attempts for: {apk_path}")
    return None


def get_decompiled_info(output_dir: str) -> Dict[str, Any]:
    """
    Gather metadata about the decompiled APK output directory.

    Returns dict with counts of smali files, resource files, etc.
    """
    info = {
        "smali_files": 0,
        "resource_files": 0,
        "has_manifest": False,
        "has_smali": False,
        "has_resources": False,
        "total_files": 0,
    }

    if not os.path.isdir(output_dir):
        return info

    info["has_manifest"] = os.path.exists(os.path.join(output_dir, "AndroidManifest.xml"))
    info["has_smali"] = os.path.isdir(os.path.join(output_dir, "smali"))
    info["has_resources"] = os.path.isdir(os.path.join(output_dir, "res"))

    for root, _dirs, files in os.walk(long_path(output_dir)):
        for f in files:
            info["total_files"] += 1
            if f.endswith(".smali"):
                info["smali_files"] += 1
            elif any(f.endswith(ext) for ext in [".xml", ".png", ".jpg", ".json"]):
                info["resource_files"] += 1

    return info
