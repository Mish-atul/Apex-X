"""
VM Orchestrator — ADB-Based Android Emulator Management (Simplified)
Manages the lifecycle of Android emulators for dynamic APK analysis:
install, launch, monkey, logcat capture, network dump, uninstall.
"""

import os
import subprocess
import time
import re
import logging
import shutil
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

logger = logging.getLogger(__name__)

# Timeouts (seconds)
ADB_COMMAND_TIMEOUT = 30
INSTALL_TIMEOUT = int(os.environ.get("APEX_INSTALL_TIMEOUT", "180"))  # install-multiple on a cold emulator can exceed 60s
MONKEY_TIMEOUT = 120
LOGCAT_PARSE_MAX = 5000

# ADB path
ADB_PATH = None


def _find_adb() -> Optional[str]:
    """Find adb binary on the system."""
    global ADB_PATH
    if ADB_PATH:
        return ADB_PATH

    result = shutil.which("adb")
    if result:
        ADB_PATH = result
        return result

    localappdata = os.environ.get("LOCALAPPDATA", "")
    android_home = os.environ.get("ANDROID_HOME", "")
    android_sdk = os.environ.get("ANDROID_SDK_ROOT", "")

    sdk_paths = [
        os.path.join(localappdata, "Android", "Sdk", "platform-tools", "adb.exe") if localappdata else "",
        os.path.join(android_home, "platform-tools", "adb.exe") if android_home else "",
        os.path.join(android_sdk, "platform-tools", "adb.exe") if android_sdk else "",
        os.path.expanduser("~/AppData/Local/Android/Sdk/platform-tools/adb.exe"),
        r"C:\Users\ASUS\AppData\Local\Android\Sdk\platform-tools\adb.exe",
        os.path.expanduser("~/Android/Sdk/platform-tools/adb"),
        os.path.expanduser("~/Library/Android/sdk/platform-tools/adb"),
    ]
    for path in sdk_paths:
        if path and os.path.isfile(path):
            ADB_PATH = path
            return path
    return None


def _run_adb(args: List[str], device: Optional[str] = None, timeout: int = ADB_COMMAND_TIMEOUT) -> Dict[str, Any]:
    """Run an ADB command and return structured result."""
    adb = _find_adb()
    if not adb:
        return {"success": False, "error": "ADB not found", "stdout": "", "stderr": ""}

    cmd = [adb]
    if device:
        cmd.extend(["-s", device])
    cmd.extend(args)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "error": result.stderr if result.returncode != 0 else None,
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"ADB timed out after {timeout}s", "stdout": "", "stderr": ""}
    except FileNotFoundError:
        return {"success": False, "error": "ADB binary not found", "stdout": "", "stderr": ""}


def is_emulator_running(include_offline: bool = False) -> Optional[str]:
    """Check if an emulator is running. Returns device serial or None."""
    result = _run_adb(["devices"])
    if not result["success"]:
        return None

    for line in result["stdout"].strip().split("\n"):
        line = line.strip()
        if "\tdevice" in line or (include_offline and "\toffline" in line):
            serial = line.split("\t")[0]
            # Emulators are typically emulator-5554, emulator-5556, etc.
            if serial.startswith("emulator-") or serial.startswith("127.0.0.1"):
                return serial

    return None


def wait_for_boot(device: str, timeout: int = 90) -> bool:
    """Wait for the device to finish booting."""
    start = time.time()
    while time.time() - start < timeout:
        result = _run_adb(["shell", "getprop", "sys.boot_completed"], device=device)
        if result["success"] and result["stdout"].strip() == "1":
            logger.info(f"Device {device} booted successfully")
            return True
        time.sleep(3)
    logger.error(f"Device {device} did not boot within {timeout}s")
    return False


def get_package_name(apk_path: str) -> Optional[str]:
    """Extract package name from an APK using aapt2 or aapt."""
    adb = _find_adb()
    if not adb:
        return None

    # Check if APK is tampered and repair first so aapt2 can parse the manifest
    target_apk = apk_path
    try:
        from app.utils.apk_repair import is_apk_tampered, repair_and_sign_apk
        tampered, _ = is_apk_tampered(apk_path)
        if tampered:
            repaired = repair_and_sign_apk(apk_path)
            if repaired and os.path.isfile(repaired):
                target_apk = repaired
    except Exception:
        pass

    # Try aapt2 first (in build-tools)
    sdk_root = os.path.dirname(os.path.dirname(adb))
    build_tools = os.path.join(sdk_root, "build-tools")

    aapt_bin = None
    if os.path.isdir(build_tools):
        for ver_dir in sorted(os.listdir(build_tools), reverse=True):
            candidate = os.path.join(build_tools, ver_dir, "aapt2.exe")
            if not os.path.isfile(candidate):
                candidate = os.path.join(build_tools, ver_dir, "aapt2")
            if os.path.isfile(candidate):
                aapt_bin = candidate
                break

    if aapt_bin:
        try:
            result = subprocess.run(
                [aapt_bin, "dump", "packagename", target_apk],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except Exception:
            pass

    # Fallback: try androguard
    try:
        from androguard.core.apk import APK
        apk = APK(target_apk)
        return apk.get_package()
    except Exception:
        pass

    return None


def install_apk(apk_path: str, package_name: str, device: Optional[str] = None) -> Dict[str, Any]:
    """Install APK on device, automatically neutralizing anti-analysis tampering."""
    logger.info(f"Installing APK: {apk_path}")
    
    # Always uninstall first to prevent INSTALL_FAILED_UPDATE_INCOMPATIBLE
    if package_name:
        logger.info(f"Pre-emptively uninstalling {package_name} to clear old signatures...")
        uninstall_apk(package_name, device=device)
        
    actual_apk_path = apk_path
    try:
        from app.utils.apk_repair import is_apk_tampered, repair_and_sign_apk
        tampered, corrupted = is_apk_tampered(apk_path)
        if tampered:
            logger.warning(f"APK anti-analysis tampering detected ({corrupted}). Repairing and re-signing before install...")
            repaired = repair_and_sign_apk(apk_path)
            if repaired and os.path.isfile(repaired):
                actual_apk_path = repaired
    except Exception as e:
        logger.warning(f"APK tamper check/repair error: {e}")

    # -g grants all runtime permissions; --bypass-low-target-sdk-block lets old
    # samples (targetSdk < 24) install on modern Android (ignored on older images).
    base_flags = ["install", "-g", "-r", "-t", "--bypass-low-target-sdk-block"]

    # Split-APK bundle: install base + all splits together with install-multiple
    try:
        from app.utils.file_utils import get_split_apks
        splits = [p for p in get_split_apks(apk_path) if os.path.isfile(p)]
    except Exception as e:
        logger.warning(f"Split lookup failed: {e}")
        splits = []
    if splits:
        logger.info(f"Split-APK bundle detected: installing base + {len(splits)} split(s) via install-multiple")

    resigned_splits: List[str] = []

    def _splits_for(path):
        # A repaired base is re-signed with the debug key; every split must carry the
        # same signature or install-multiple fails, so re-sign copies of the splits too.
        if not splits or path == apk_path:
            return splits
        if not resigned_splits:
            from app.utils.apk_repair import sign_apk_copy
            for s in splits:
                signed = sign_apk_copy(s)
                if not signed:
                    logger.warning(f"Could not re-sign split {s}; installing original")
                resigned_splits.append(signed or s)
        return resigned_splits

    def _install(path):
        cmd = "install-multiple" if splits else "install"
        paths = [path] + _splits_for(path)
        res = _run_adb([cmd] + base_flags[1:] + paths, device=device, timeout=INSTALL_TIMEOUT)
        if not res["success"] and "bypass-low-target-sdk-block" in (res.get("error") or ""):
            # Flag unsupported on this API level — retry without it
            res = _run_adb([cmd, "-g", "-r", "-t"] + paths, device=device, timeout=INSTALL_TIMEOUT)
        return res

    result = _install(actual_apk_path)
    if not result["success"] and "not enough space" in (result.get("error") or "") + result.get("stdout", ""):
        logger.warning("Device storage low; trimming caches and retrying install")
        _run_adb(["shell", "pm", "trim-caches", "999G"], device=device, timeout=120)
        result = _install(actual_apk_path)
    
    # If install failed due to parse error, invalid cert, or corrupt headers, try repair fallback
    if not result["success"] and actual_apk_path == apk_path:
        err = result.get("error", "")
        if any(tok in err for tok in ["INSTALL_PARSE_FAILED", "INSTALL_FAILED_INVALID_APK", "INSTALL_FAILED_NO_CERTIFICATES", "Failed to parse", "CORRUPT"]):
            logger.warning(f"Install failed with parse/cert error: {err}. Attempting APK header repair & re-sign...")
            try:
                from app.utils.apk_repair import repair_and_sign_apk
                repaired = repair_and_sign_apk(apk_path)
                if repaired and os.path.isfile(repaired):
                    result = _install(repaired)
            except Exception as e:
                logger.error(f"Fallback APK repair failed: {e}")

    if result["success"]:
        logger.info("APK installed successfully")
        
        # Manually grant critical AppOps permissions that -g misses (e.g. Draw Overlays)
        # Banking trojans crash if this is missing!
        _run_adb(["shell", "appops", "set", package_name, "SYSTEM_ALERT_WINDOW", "allow"], device=device)
        # Try to grant accessibility if requested
        _run_adb(["shell", "appops", "set", package_name, "PROJECT_MEDIA", "allow"], device=device)
    else:
        logger.error(f"APK install failed: {result['error']}")
    return result

def uninstall_apk(package_name: str, device: Optional[str] = None) -> Dict[str, Any]:
    """Uninstall an APK by package name."""
    logger.info(f"Uninstalling: {package_name}")
    return _run_adb(["uninstall", package_name], device=device)


def launch_app(package_name: str, device: Optional[str] = None) -> Dict[str, Any]:
    """Launch an app bypassing anti-analysis activity crashers."""
    
    # Try launching via standard Monkey intents (bypasses decoy activities)
    categories = ["LAUNCHER", "INFO", "DEFAULT", "MONKEY"]
    for cat in categories:
        logger.info(f"Trying to launch {package_name} via category {cat}")
        res = _run_adb(["shell", "monkey", "-p", package_name, "-c", f"android.intent.category.{cat}", "1"], device=device)
        if "No activities found to run" not in res.get("stderr", "") + res.get("stdout", "") and res["success"]:
            logger.info(f"Successfully launched {package_name} via {cat}")
            
            # Forcefully trigger BOOT_COMPLETED to wake up background services
            _run_adb(["shell", "am", "broadcast", "-a", "android.intent.action.BOOT_COMPLETED", "-p", package_name], device=device)
            return res

    # Fallback to manual am start if Monkey fails completely
    activity = None
    result = _run_adb(
        ["shell", "cmd", "package", "resolve-activity", "--brief", package_name],
        device=device
    )
    if result["success"]:
        for line in result["stdout"].strip().split("\n"):
            if "/" in line and package_name in line:
                activity = line.strip()
                break

    if not activity:
        dump = _run_adb(["shell", "dumpsys", "package", package_name], device=device)
        if dump["success"]:
            lines = dump["stdout"].split("\n")
            in_main = False
            for line in lines:
                if "android.intent.action.MAIN:" in line:
                    in_main = True
                elif in_main and package_name in line and "filter" in line:
                    parts = line.strip().split()
                    if len(parts) >= 2 and "/" in parts[1]:
                        activity = parts[1]
                        break
                elif in_main and "Action:" not in line and "Category:" not in line:
                    in_main = False

    # Forcefully trigger BOOT_COMPLETED (many malwares rely on this to start services)
    logger.info(f"Triggering BOOT_COMPLETED for {package_name}")
    _run_adb(["shell", "am", "broadcast", "-a", "android.intent.action.BOOT_COMPLETED", "-p", package_name], device=device)

    if activity:
        logger.info(f"Launching activity: {activity}")
        return _run_adb(["shell", "am", "start", "-n", activity], device=device)
    else:
        # Final fallback: monkey launch
        logger.info("No main activity found, falling back to monkey")
        return _run_adb(
            ["shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"],
            device=device
        )


def run_monkey(package_name: str, events: int = 500, device: Optional[str] = None) -> Dict[str, Any]:
    """Run Android Monkey for random UI interactions."""
    logger.info(f"Running Monkey: {events} events on {package_name}")
    
    # Try package-specific monkey first
    result = _run_adb(
        ["shell", "monkey", "-p", package_name, "--throttle", "100",
         "--ignore-crashes", "--ignore-timeouts", "--ignore-security-exceptions",
         "-v", str(events)],
        device=device,
        timeout=MONKEY_TIMEOUT
    )
    
    # Many malwares don't export standard launcher categories to evade Monkey.
    # If monkey aborts, run system-wide monkey which will click around whatever is currently 
    # on screen (which is our app, since we just launched it in step 4).
    stdout = result.get("stdout", "")
    if "monkey aborted" in stdout:
        logger.warning(f"Package monkey aborted. Falling back to system-wide screen monkey.")
        result = _run_adb(
            ["shell", "monkey", "--throttle", "100",
             "--ignore-crashes", "--ignore-timeouts", "--ignore-security-exceptions",
             "-v", str(events)],
            device=device,
            timeout=MONKEY_TIMEOUT
        )
        
    return result


def capture_logcat(device: Optional[str] = None, duration: int = 5) -> str:
    """Capture logcat output. Clear first, then capture for duration."""
    # Clear existing logcat
    _run_adb(["logcat", "-c"], device=device)

    time.sleep(duration)

    # Dump logcat
    result = _run_adb(["logcat", "-d", "-v", "time"], device=device, timeout=30)
    if result["success"]:
        return result["stdout"]
    return ""


def start_logcat_capture(device: Optional[str] = None) -> None:
    """Clear logcat buffer to start fresh capture."""
    _run_adb(["logcat", "-c"], device=device)


def collect_logcat(device: Optional[str] = None) -> str:
    """Collect all logcat since last clear."""
    result = _run_adb(["logcat", "-d", "-v", "threadtime"], device=device, timeout=30)
    return result["stdout"] if result["success"] else ""


def dump_network_stats(device: Optional[str] = None) -> Dict[str, Any]:
    """Get network statistics from device."""
    stats: Dict[str, Any] = {"connections": [], "dns_queries": []}

    # Get active connections
    result = _run_adb(["shell", "cat", "/proc/net/tcp"], device=device)
    if result["success"]:
        for line in result["stdout"].strip().split("\n")[1:]:  # skip header
            parts = line.split()
            if len(parts) >= 4:
                # Parse hex IP:port
                try:
                    remote = parts[2]
                    hex_ip, hex_port = remote.split(":")
                    port = int(hex_port, 16)
                    # Convert hex IP to dotted
                    ip_int = int(hex_ip, 16)
                    ip = f"{ip_int & 0xFF}.{(ip_int >> 8) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 24) & 0xFF}"
                    if ip != "0.0.0.0" and port != 0:
                        # Filter out common Google/system IP ranges
                        is_system = False
                        if ip.startswith("10.") or ip.startswith("127.") or ip.startswith("192.168."):
                            is_system = True
                        elif ip.startswith("216.239.") or ip.startswith("216.58.") or ip.startswith("142.250.") or ip.startswith("142.251."):
                            is_system = True
                        elif ip.startswith("172.217.") or ip.startswith("8.8."):
                            is_system = True
                            
                        # Try reverse DNS lookup
                        domain = ip
                        try:
                            import socket
                            domain_info = socket.gethostbyaddr(ip)
                            if domain_info and domain_info[0]:
                                domain = domain_info[0]
                        except Exception:
                            domain = f"Unresolved ({ip})"
                            
                        stats["connections"].append({
                            "remote_ip": ip,
                            "remote_port": port,
                            "protocol": "TCP",
                            "is_system": is_system,
                            "domain": domain
                        })
                except Exception:
                    continue

    # Get dumpsys connectivity info
    result = _run_adb(["shell", "dumpsys", "connectivity"], device=device)
    if result["success"]:
        stats["connectivity_dump"] = result["stdout"][:2000]  # Cap size

    return stats


def parse_logcat_events(logcat_output: str, package_name: str) -> List[Dict[str, Any]]:
    """
    Parse logcat output into structured behavioral events.
    Looks for API calls, network activity, exceptions, intents.
    """
    events: List[Dict[str, Any]] = []
    event_id = 0
    seen: set = set()

    # Patterns to detect in logcat
    patterns = [
        # Network
        (r"(https?://[^\s\"']+)", "network", "HTTP Request", "MEDIUM"),
        (r"Connecting to\s+([\w\.\-]+)", "network", "Connection Attempt", "MEDIUM"),
        (r"dns_query.*?(\S+\.\S+)", "network", "DNS Query", "MEDIUM"),

        # Security exceptions
        (r"SecurityException:\s*(.+)", "security", "Security Exception", "HIGH"),
        (r"Permission denied.*?(\S+)", "security", "Permission Denied", "MEDIUM"),

        # Crypto
        (r"Cipher.*?(AES|DES|RSA|CBC|GCM)", "crypto", "Cipher Operation", "MEDIUM"),

        # File I/O
        (r"(\/sdcard\/[^\s]+|\/storage\/[^\s]+)", "file_io", "File Access", "MEDIUM"),
        (r"SharedPreferences.*?(put|get|edit)", "file_io", "SharedPreferences Access", "LOW"),

        # Dynamic loading
        (r"DexClassLoader|InMemoryDexClassLoader", "dynamic_loading", "Dynamic Code Loading", "CRITICAL"),
        (r"dlopen\((.+?)\)", "dynamic_loading", "Native Library Load", "HIGH"),

        # SMS
        (r"SmsManager|sendTextMessage", "sms", "SMS Operation", "CRITICAL"),

        # Device info
        (r"getDeviceId|getImei|getSubscriberId", "data_exfil", "Device ID Access", "HIGH"),
    ]

    lines = logcat_output.split("\n")
    for line in lines[:LOGCAT_PARSE_MAX]:

        for pattern, category, title, risk in patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                detail = match.group(1) if match.lastindex else match.group(0)
                dedup = (category, title, detail[:50])
                if dedup in seen:
                    continue
                seen.add(dedup)

                # Extract timestamp from logcat line
                ts_match = re.match(r"(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)", line)
                timestamp = ts_match.group(1) if ts_match else datetime.now(timezone.utc).isoformat()

                event_id += 1
                events.append({
                    "id": f"logcat-{event_id}",
                    "timestamp": str(timestamp),
                    "category": category,
                    "api_call": title,
                    "class_name": package_name,
                    "risk_level": risk,
                    "description": detail[:200],
                    "source": "logcat_runtime",
                    "raw_line": line[:300],
                })

    # Add Application Started and Analysis Complete events for sequence logic
    base_ts = datetime.now(timezone.utc)
    if events:
        try:
            # Try to get the earliest timestamp, else use now
            # logcat timestamp format: "07-04 12:34:56.789"
            first_event = min(events, key=lambda x: x["timestamp"])
            if "-" in first_event["timestamp"] and ":" in first_event["timestamp"]:
                # Just mock an ISO for sorting in UI if it's raw logcat
                events_sorted = True
        except Exception:
            pass

    events.insert(0, {
        "id": "logcat-0-start",
        "timestamp": base_ts.isoformat(),
        "category": "system",
        "api_call": "Application Started",
        "class_name": package_name,
        "risk_level": "LOW",
        "description": "App launched by orchestrator",
        "source": "orchestrator",
        "raw_line": "",
    })

    # Also look for crashes/ANRs
    crash_pattern = re.compile(
        rf"FATAL EXCEPTION.*?{re.escape(package_name)}.*?$\n(.*?)$",
        re.MULTILINE
    )
    for match in crash_pattern.finditer(logcat_output):
        event_id += 1
        events.append({
            "id": f"logcat-{event_id}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "category": "crash",
            "api_call": "FATAL EXCEPTION",
            "class_name": package_name,
            "risk_level": "HIGH",
            "description": match.group(1)[:300],
            "source": "logcat_runtime",
        })
        
    events.append({
        "id": f"logcat-999-end",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "category": "system",
        "api_call": "Analysis Complete",
        "class_name": package_name,
        "risk_level": "LOW",
        "description": "Automated execution finished",
        "source": "orchestrator",
        "raw_line": "",
    })

    return events
