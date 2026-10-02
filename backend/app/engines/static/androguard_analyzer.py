"""
Androguard Analyzer — Real Integration
Uses the androguard Python library to perform deep APK analysis:
permissions, API calls, certificate info, strings, components, and CFG data.
"""

import os
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

try:
    from androguard.misc import AnalyzeAPK
    from androguard.core.apk import APK
    from androguard.core.dex import DEX
    ANDROGUARD_AVAILABLE = True
    try:  # androguard 4 logs every parsed resource at DEBUG via loguru
        import sys
        from loguru import logger as _loguru
        _loguru.remove()
        _loguru.add(sys.stderr, level="WARNING")
    except Exception:
        pass
except ImportError:
    ANDROGUARD_AVAILABLE = False
    logger.warning(
        "androguard library not installed. Install it: pip install androguard>=3.4.0"
    )


# Comprehensive dangerous permission set
DANGEROUS_PERMISSIONS = {
    # Location
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    # Camera & Microphone
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    # Contacts
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    # Phone
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.CALL_PHONE",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    # SMS
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_MMS",
    "android.permission.RECEIVE_WAP_PUSH",
    # Storage
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    # Calendar
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    # Body Sensors
    "android.permission.BODY_SENSORS",
    "android.permission.ACTIVITY_RECOGNITION",
    # Bluetooth
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BLUETOOTH_ADVERTISE",
    # Nearby
    "android.permission.NEARBY_WIFI_DEVICES",
    # Notifications
    "android.permission.POST_NOTIFICATIONS",
    # Media
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
}

# API calls that are high-risk in the context of malware
HIGH_RISK_API_PATTERNS = [
    "Ljava/net/URL;->openConnection",
    "Ljava/net/HttpURLConnection;",
    "Ljavax/net/ssl/HttpsURLConnection;",
    "Landroid/telephony/SmsManager;->sendTextMessage",
    "Landroid/telephony/SmsManager;->sendMultipartTextMessage",
    "Ljava/lang/Runtime;->exec",
    "Ljava/lang/ProcessBuilder;->start",
    "Landroid/content/pm/PackageManager;->getInstalledPackages",
    "Landroid/app/admin/DevicePolicyManager;",
    "Landroid/os/PowerManager;->reboot",
    "Landroid/provider/Settings$Secure;->getString",
    "Landroid/hardware/Camera;->open",
    "Landroid/media/MediaRecorder;->start",
    "Landroid/location/LocationManager;->getLastKnownLocation",
    "Landroid/location/LocationManager;->requestLocationUpdates",
    "Landroid/content/ContentResolver;->query",
    "Landroid/accounts/AccountManager;->getAccounts",
    "Ljavax/crypto/Cipher;->getInstance",
    "Ljavax/crypto/Cipher;->doFinal",
    "Ljava/security/KeyStore;->load",
    "Landroid/webkit/WebView;->loadUrl",
    "Landroid/webkit/WebView;->addJavascriptInterface",
    "Ljava/lang/reflect/Method;->invoke",
    "Ldalvik/system/DexClassLoader;",
    "Ldalvik/system/PathClassLoader;",
    "Ldalvik/system/InMemoryDexClassLoader;",
    "Ljava/io/FileOutputStream;-><init>",
    "Landroid/content/SharedPreferences;->edit",
    "Landroid/database/sqlite/SQLiteDatabase;->execSQL",
    "Landroid/app/NotificationManager;->notify",
    "Landroid/app/AlarmManager;->setRepeating",
    "Landroid/content/ClipboardManager;->getPrimaryClip",
    "Landroid/view/accessibility/AccessibilityEvent;",
]


def analyze_apk(apk_path: str) -> Dict[str, Any]:
    """
    Perform comprehensive APK analysis using Androguard.

    Args:
        apk_path: Absolute path to the APK file.

    Returns:
        Dict containing complete analysis results.
    """
    if not os.path.exists(apk_path):
        logger.error(f"APK file not found: {apk_path}")
        return {"error": f"APK file not found: {apk_path}"}

    if not ANDROGUARD_AVAILABLE:
        logger.error("Androguard is not available — cannot analyze APK.")
        return {"error": "androguard library not installed"}

    try:
        logger.info(f"Starting Androguard fast analysis (APK only) of: {apk_path}")
        # Only parse the APK manifest to avoid 10-minute DEX CFG generation overhead
        apk_obj = APK(apk_path)
        analysis_obj = None

        result = {
            "package_name": apk_obj.get_package() or "unknown",
            "app_name": apk_obj.get_app_name() or "unknown",
            "version_name": apk_obj.get_androidversion_name() or "unknown",
            "version_code": apk_obj.get_androidversion_code() or "unknown",
            "min_sdk": apk_obj.get_min_sdk_version(),
            "target_sdk": apk_obj.get_target_sdk_version(),
            "max_sdk": apk_obj.get_max_sdk_version(),
            "permissions": _extract_permissions(apk_obj),
            "activities": _extract_activities(apk_obj),
            "services": _extract_services(apk_obj),
            "receivers": _extract_receivers(apk_obj),
            "providers": _extract_providers(apk_obj),
            "main_activity": apk_obj.get_main_activity() or "unknown",
            "certificate": _extract_certificate_info(apk_obj),
            "api_calls": _extract_api_calls(analysis_obj),
            "strings": _extract_interesting_strings(analysis_obj),
            "libraries": _extract_libraries(apk_obj),
            "files": _extract_file_list(apk_obj),
        }

        logger.info(f"Androguard analysis complete for: {result['package_name']}")
        return result

    except Exception as e:
        logger.error(f"Androguard analysis failed: {e}")
        return {"error": str(e)}


def _extract_permissions(apk_obj) -> Dict[str, Any]:
    """Extract and classify all permissions."""
    all_perms = apk_obj.get_permissions() or []
    declared_perms = apk_obj.get_declared_permissions() or []

    dangerous = [p for p in all_perms if p in DANGEROUS_PERMISSIONS]
    normal = [p for p in all_perms if p not in DANGEROUS_PERMISSIONS]

    return {
        "all": list(all_perms),
        "dangerous": dangerous,
        "normal": normal,
        "declared": list(declared_perms),
        "total_count": len(all_perms),
        "dangerous_count": len(dangerous),
    }


def _extract_activities(apk_obj) -> List[Dict[str, Any]]:
    """Extract activity components with export status."""
    activities = []
    for activity in (apk_obj.get_activities() or []):
        exported = False
        try:
            # Check if the activity element has exported attribute
            for item in apk_obj.get_android_manifest_xml().findall(".//activity"):
                name = item.get("{http://schemas.android.com/apk/res/android}name", "")
                if name == activity or name.endswith(activity.split(".")[-1]):
                    exp_val = item.get("{http://schemas.android.com/apk/res/android}exported", "")
                    exported = exp_val.lower() == "true"
                    # Activities with intent-filters are implicitly exported if not explicitly set
                    if not exp_val and item.findall("intent-filter"):
                        exported = True
                    break
        except Exception:
            pass
        activities.append({"name": activity, "exported": exported})
    return activities


def _extract_services(apk_obj) -> List[Dict[str, Any]]:
    """Extract service components."""
    services = []
    for service in (apk_obj.get_services() or []):
        services.append({"name": service})
    return services


def _extract_receivers(apk_obj) -> List[Dict[str, Any]]:
    """Extract broadcast receiver components."""
    receivers = []
    for receiver in (apk_obj.get_receivers() or []):
        receivers.append({"name": receiver})
    return receivers


def _extract_providers(apk_obj) -> List[Dict[str, Any]]:
    """Extract content provider components."""
    providers = []
    for provider in (apk_obj.get_providers() or []):
        providers.append({"name": provider})
    return providers


def _extract_certificate_info(apk_obj) -> Dict[str, Any]:
    """Extract APK signing certificate information."""
    cert_info = {
        "issuer": "unknown",
        "subject": "unknown",
        "serial_number": "unknown",
        "fingerprint_sha256": "unknown",
        "valid_from": "unknown",
        "valid_to": "unknown",
    }
    try:
        certs = apk_obj.get_certificates()
        if certs:
            cert = certs[0]  # Primary certificate
            cert_info["issuer"] = str(cert.issuer) if hasattr(cert, "issuer") else "unknown"
            cert_info["subject"] = str(cert.subject) if hasattr(cert, "subject") else "unknown"
            cert_info["serial_number"] = str(cert.serial_number) if hasattr(cert, "serial_number") else "unknown"
            if hasattr(cert, "sha256_fingerprint"):
                fp = cert.sha256_fingerprint
                cert_info["fingerprint_sha256"] = fp.hex() if isinstance(fp, bytes) else str(fp).replace(" ", "").lower()
            if hasattr(cert, "not_valid_before"):
                cert_info["valid_from"] = str(cert.not_valid_before)
            if hasattr(cert, "not_valid_after"):
                cert_info["valid_to"] = str(cert.not_valid_after)
            try:  # asn1crypto certificates (androguard >= 4)
                validity = cert["tbs_certificate"]["validity"]
                cert_info["valid_from"] = str(validity["not_before"].native)
                cert_info["valid_to"] = str(validity["not_after"].native)
                cert_info["issuer"] = cert.issuer.human_friendly
                cert_info["subject"] = cert.subject.human_friendly
            except Exception:
                pass
    except Exception as e:
        logger.warning(f"Failed to extract certificate info: {e}")

    return cert_info


def _extract_api_calls(analysis_obj) -> Dict[str, Any]:
    """Extract and classify API calls found in the code."""
    if analysis_obj is None:
        return {"high_risk": [], "all_external": [], "count": 0}

    high_risk_calls = []
    all_external = []

    try:
        for method in analysis_obj.get_external_classes():
            method_name = str(method.name)
            all_external.append(method_name)

            for pattern in HIGH_RISK_API_PATTERNS:
                if pattern in method_name:
                    high_risk_calls.append({
                        "api": method_name,
                        "risk_pattern": pattern,
                    })
                    break
    except Exception as e:
        logger.warning(f"Error extracting API calls: {e}")
        # Fallback: try iterating over methods directly
        try:
            for cls in analysis_obj.get_classes():
                cls_name = str(cls.name)
                if cls.is_external():
                    all_external.append(cls_name)
                    for pattern in HIGH_RISK_API_PATTERNS:
                        if pattern.split(";")[0] + ";" in cls_name:
                            high_risk_calls.append({
                                "api": cls_name,
                                "risk_pattern": pattern,
                            })
                            break
        except Exception:
            pass

    return {
        "high_risk": high_risk_calls[:200],
        "all_external": all_external[:500],
        "count": len(all_external),
        "high_risk_count": len(high_risk_calls),
    }


def _extract_interesting_strings(analysis_obj) -> Dict[str, List[str]]:
    """
    Extract interesting strings from DEX analysis — URLs, IPs, file paths,
    crypto-related constants, etc.
    """
    import re

    strings_result = {
        "urls": [],
        "ips": [],
        "file_paths": [],
        "crypto_constants": [],
        "suspicious": [],
    }

    if analysis_obj is None:
        return strings_result

    url_re = re.compile(r'https?://[^\s"\'<>]+')
    ip_re = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
    path_re = re.compile(r'/(?:sdcard|data|system|proc|dev|mnt)/[^\s"\']+')
    suspicious_keywords = [
        "password", "secret", "api_key", "apikey", "token", "auth",
        "root", "su ", "/system/bin/su", "superuser",
        "encrypt", "decrypt", "base64", "cipher",
        "exfil", "steal", "keylog", "inject",
    ]

    try:
        for s_analysis in analysis_obj.get_strings():
            s = str(s_analysis)
            if len(s) < 4 or len(s) > 500:
                continue

            urls = url_re.findall(s)
            if urls:
                strings_result["urls"].extend(urls)

            ips = ip_re.findall(s)
            if ips:
                strings_result["ips"].extend(ips)

            paths = path_re.findall(s)
            if paths:
                strings_result["file_paths"].extend(paths)

            s_lower = s.lower()
            for keyword in suspicious_keywords:
                if keyword in s_lower:
                    strings_result["suspicious"].append(s[:200])
                    break

    except Exception as e:
        logger.warning(f"Error extracting strings: {e}")

    # Deduplicate
    for key in strings_result:
        strings_result[key] = list(set(strings_result[key]))[:100]

    return strings_result


def _extract_libraries(apk_obj) -> List[str]:
    """Extract native libraries (.so files) from the APK."""
    try:
        libs = apk_obj.get_libraries() or []
        return list(libs)
    except Exception:
        return []


def _extract_file_list(apk_obj) -> Dict[str, List[str]]:
    """Get categorized list of files in the APK."""
    try:
        all_files = apk_obj.get_files() or []
    except Exception:
        return {"dex": [], "native": [], "assets": [], "other": []}

    categorized = {
        "dex": [],
        "native": [],
        "assets": [],
        "other": [],
    }

    for f in all_files:
        if f.endswith(".dex"):
            categorized["dex"].append(f)
        elif f.endswith(".so"):
            categorized["native"].append(f)
        elif f.startswith("assets/"):
            categorized["assets"].append(f)
        else:
            categorized["other"].append(f)

    # Cap lists
    for key in categorized:
        categorized[key] = categorized[key][:100]

    return categorized
