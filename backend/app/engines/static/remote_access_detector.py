"""
Remote Access Detector
Flags the specific combination of Accessibility Service + draw-over-other-apps
permission + a bundled remote-desktop SDK as a highly distinctive pattern
for screen-share / remote-access scams.
"""

from app.utils.file_utils import long_path
import os
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

KNOWN_REMOTE_SDK_SIGNATURES = {
    "com/teamviewer": "TeamViewer QuickSupport SDK",
    "com/anydesk": "AnyDesk SDK",
    "com/teamviewer/quicksupport": "TeamViewer QuickSupport SDK",
    "com/rustdesk": "RustDesk SDK",
    "com/awesun": "AweSun SDK",
    "com/splashtop": "Splashtop SDK",
}

def detect_remote_access_abuse(manifest_data: Dict[str, Any], apktool_dir: str) -> Dict[str, Any]:
    """
    Checks manifest_data["permissions"] for BIND_ACCESSIBILITY_SERVICE and
    SYSTEM_ALERT_WINDOW together, then scans smali/resource package names in
    apktool_dir against KNOWN_REMOTE_SDK_SIGNATURES.
    """
    result = {
        "flagged": False,
        "accessibility_service": False,
        "overlay_permission": False,
        "bundled_sdk": None
    }

    if not manifest_data or not apktool_dir or not os.path.isdir(apktool_dir):
        return result

    permissions = manifest_data.get("permissions", {})
    if isinstance(permissions, dict):
        all_perms = permissions.get("all", permissions.get("dangerous", []))
    elif isinstance(permissions, list):
        all_perms = permissions
    else:
        all_perms = []

    all_perms_upper = [p.upper() if isinstance(p, str) else "" for p in all_perms]

    result["accessibility_service"] = any("BIND_ACCESSIBILITY_SERVICE" in p for p in all_perms_upper)
    result["overlay_permission"] = any("SYSTEM_ALERT_WINDOW" in p for p in all_perms_upper)

    # If both permissions aren't present, it's not the classic remote access MO
    if not (result["accessibility_service"] and result["overlay_permission"]):
        return result

    # Scan for SDKs in smali folders
    smali_dirs = [d for d in os.listdir(apktool_dir) if d.startswith("smali") and os.path.isdir(os.path.join(apktool_dir, d))]
    
    found_sdk = None
    for smali_dir in smali_dirs:
        smali_path = os.path.join(apktool_dir, smali_dir)
        for root, dirs, _ in os.walk(long_path(smali_path)):
            rel_path = os.path.relpath(root, long_path(smali_path))
            # normalize path separator for comparison
            normalized_path = rel_path.replace("\\", "/")
            
            for sig_path, sdk_name in KNOWN_REMOTE_SDK_SIGNATURES.items():
                if sig_path in normalized_path:
                    found_sdk = sdk_name
                    break
            
            if found_sdk:
                break
        if found_sdk:
            break

    if found_sdk:
        result["bundled_sdk"] = found_sdk
        result["flagged"] = True
        logger.warning(f"Remote access abuse detected! SDK: {found_sdk}")

    return result
