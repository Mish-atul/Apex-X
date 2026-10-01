"""
Device Monitor — Manual Penetration Testing Engine
Connects to physical Android devices via USB/ADB, monitors all activity
in real-time while the investigator manually interacts with the APK,
and detects child/dropper APK installations that hide in the background.

Integrates PCAPdroid for full packet-level network capture.
"""

import os
import re
import json
import time
import shutil
import logging
import threading
import subprocess
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from uuid import uuid4

from app.engines.dynamic import vm_orchestrator

logger = logging.getLogger(__name__)

# ── Active Monitoring Sessions ──────────────────────────────────────
_active_sessions: Dict[str, Dict[str, Any]] = {}

PCAPDROID_PACKAGE = "com.emanuelef.remote_capture"
PCAPDROID_APK_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))),
    "tools", "PCAPdroid.apk"
)

# ── USB Device Scanning ─────────────────────────────────────────────

def scan_usb_devices() -> List[Dict[str, Any]]:
    """
    Scan for physical Android devices connected via USB.
    Filters out emulators (emulator-XXXX, 127.0.0.1:XXXX).
    Handles 'device', 'unauthorized', and 'offline' states.
    """
    result = vm_orchestrator._run_adb(["devices", "-l"])
    if not result["success"]:
        return []

    devices = []
    for line in result["stdout"].strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("List of"):
            continue

        parts = line.split()
        if len(parts) < 2:
            continue

        serial = parts[0]
        status = parts[1].lower()

        # Skip emulators
        if serial.startswith("emulator-") or serial.startswith("127.0.0.1") or serial.startswith("localhost:"):
            continue

        # Extract extra info from key:value tokens in 'adb devices -l' output (e.g. model:M2006C3LI)
        props_from_line = {}
        for token in parts[2:]:
            if ":" in token:
                k, v = token.split(":", 1)
                props_from_line[k] = v

        model_inline = props_from_line.get("model", "")
        product_inline = props_from_line.get("product", "")
        device_inline = props_from_line.get("device", "")

        if status == "unauthorized":
            devices.append({
                "serial": serial,
                "model": model_inline or "Android Device",
                "brand": "Unauthorized",
                "android_version": "?",
                "sdk_version": "?",
                "status": "unauthorized",
                "display_name": f"⚠️ {model_inline or serial} (Unauthorized - Allow USB Debugging on phone screen)",
            })
            continue

        if status == "offline":
            devices.append({
                "serial": serial,
                "model": model_inline or "Android Device",
                "brand": "Offline",
                "android_version": "?",
                "sdk_version": "?",
                "status": "offline",
                "display_name": f"⚠️ {model_inline or serial} (Offline - Reconnect USB cable)",
            })
            continue

        if status == "device":
            # Query properties from device, fallback to inline properties
            model = _get_device_prop(serial, "ro.product.model") or model_inline or "Android Device"
            brand = _get_device_prop(serial, "ro.product.brand") or product_inline or "Generic"
            android_version = _get_device_prop(serial, "ro.build.version.release") or "?"
            sdk_version = _get_device_prop(serial, "ro.build.version.sdk") or "?"

            devices.append({
                "serial": serial,
                "model": model,
                "brand": brand,
                "android_version": android_version,
                "sdk_version": sdk_version,
                "status": "ready",
                "display_name": f"📱 {brand.capitalize()} {model} (Android {android_version})",
            })

    return devices


def _get_device_prop(serial: str, prop: str) -> Optional[str]:
    """Get a system property from the device."""
    result = vm_orchestrator._run_adb(["shell", "getprop", prop], device=serial, timeout=5)
    if result["success"]:
        return result["stdout"].strip()
    return None


# ── PCAPdroid Management ────────────────────────────────────────────

def _is_pcapdroid_installed(device: str) -> bool:
    """Check if PCAPdroid is installed on the device."""
    result = vm_orchestrator._run_adb(
        ["shell", "pm", "list", "packages", PCAPDROID_PACKAGE],
        device=device, timeout=10
    )
    return result["success"] and PCAPDROID_PACKAGE in result["stdout"]


def _install_pcapdroid(device: str) -> bool:
    """Install PCAPdroid on the device."""
    if _is_pcapdroid_installed(device):
        logger.info("PCAPdroid already installed")
        return True

    if not os.path.exists(PCAPDROID_APK_PATH):
        logger.warning(f"PCAPdroid APK not found at {PCAPDROID_APK_PATH}. "
                       "Network capture will fall back to ADB-only mode.")
        return False

    logger.info(f"Installing PCAPdroid on {device}...")
    result = vm_orchestrator._run_adb(
        ["install", "-r", "-g", PCAPDROID_APK_PATH],
        device=device, timeout=60
    )
    if result["success"]:
        logger.info("PCAPdroid installed successfully")
        return True
    else:
        logger.error(f"PCAPdroid install failed: {result.get('error')}")
        return False


def _start_pcapdroid_capture(device: str, pcap_dir: str) -> bool:
    """Start PCAPdroid packet capture via intent API."""
    # Configure PCAPdroid to save PCAP to the device's sdcard
    device_pcap_path = "/sdcard/apex_capture.pcap"

    # Start capture via broadcast intent
    result = vm_orchestrator._run_adb([
        "shell", "am", "broadcast",
        "-a", "com.emanuelef.remote_capture.START",
        "-n", f"{PCAPDROID_PACKAGE}/.CaptureCtrl",
        "--es", "pcap_dump_mode", "pcap_file",
        "--es", "pcap_name", device_pcap_path,
    ], device=device, timeout=10)

    if result["success"]:
        logger.info("PCAPdroid capture started")
        return True
    else:
        logger.warning(f"PCAPdroid start failed: {result.get('error')}")
        return False


def _stop_pcapdroid_capture(device: str, output_dir: str) -> Optional[str]:
    """Stop PCAPdroid capture and pull the PCAP file."""
    # Stop capture via broadcast intent
    vm_orchestrator._run_adb([
        "shell", "am", "broadcast",
        "-a", "com.emanuelef.remote_capture.STOP",
        "-n", f"{PCAPDROID_PACKAGE}/.CaptureCtrl",
    ], device=device, timeout=10)

    time.sleep(2)  # Let PCAPdroid flush

    # Pull the PCAP file
    device_pcap_path = "/sdcard/apex_capture.pcap"
    local_pcap_path = os.path.join(output_dir, "network_capture.pcap")

    result = vm_orchestrator._run_adb(
        ["pull", device_pcap_path, local_pcap_path],
        device=device, timeout=30
    )

    if result["success"] and os.path.exists(local_pcap_path):
        # Clean up device
        vm_orchestrator._run_adb(
            ["shell", "rm", device_pcap_path],
            device=device, timeout=5
        )
        logger.info(f"PCAP pulled to {local_pcap_path}")
        return local_pcap_path
    else:
        logger.warning("Could not pull PCAP file from device")
        return None


# ── Package Snapshot & Diff ─────────────────────────────────────────

def _clean_package_name(raw: str) -> str:
    """Ensure a package string is just the pure package name without paths or '='."""
    p = raw.strip()
    if p.startswith("package:"):
        p = p[len("package:"):].strip()
    if "=" in p:
        p = p.rsplit("=", 1)[-1].strip()
    if "/" in p:
        p = p.rsplit("/", 1)[-1].strip()
    return p


def _snapshot_packages(device: str) -> set:
    """
    Take a comprehensive snapshot of ALL installed packages on the device.
    Uses multiple strategies to catch packages installed under different users,
    disabled packages, and packages that might be hidden from the standard list.
    """
    packages = set()

    # Strategy 1: Standard package list (all packages for current user)
    result = vm_orchestrator._run_adb(
        ["shell", "pm", "list", "packages"],
        device=device, timeout=15
    )
    if result["success"]:
        for line in result["stdout"].strip().split("\n"):
            line = line.strip()
            if line.startswith("package:"):
                pkg = _clean_package_name(line)
                if pkg:
                    packages.add(pkg)

    # Strategy 2: Include disabled packages (malware may disable itself to hide)
    result2 = vm_orchestrator._run_adb(
        ["shell", "pm", "list", "packages", "-d"],
        device=device, timeout=15
    )
    if result2["success"]:
        for line in result2["stdout"].strip().split("\n"):
            line = line.strip()
            if line.startswith("package:"):
                pkg = _clean_package_name(line)
                if pkg:
                    packages.add(pkg)

    # Strategy 3: Third-party packages only (catches sideloaded malware)
    result3 = vm_orchestrator._run_adb(
        ["shell", "pm", "list", "packages", "-3"],
        device=device, timeout=15
    )
    if result3["success"]:
        for line in result3["stdout"].strip().split("\n"):
            line = line.strip()
            if line.startswith("package:"):
                pkg = _clean_package_name(line)
                if pkg:
                    packages.add(pkg)

    # Strategy 4: Include uninstalled packages (malware may install-then-uninstall)
    result4 = vm_orchestrator._run_adb(
        ["shell", "pm", "list", "packages", "-u"],
        device=device, timeout=15
    )
    if result4["success"]:
        for line in result4["stdout"].strip().split("\n"):
            line = line.strip()
            if line.startswith("package:"):
                pkg = _clean_package_name(line)
                if pkg:
                    packages.add(pkg)

    logger.debug(f"[Snapshot] Captured {len(packages)} total packages on {device}")
    return packages


def _analyze_new_package(device: str, package_name: str) -> Dict[str, Any]:
    """Analyze a newly installed package for suspicious traits."""
    info = {
        "package_name": package_name,
        "has_launcher_icon": False,
        "is_hidden": True,
        "is_running": False,
        "permissions": [],
        "install_path": "",
        "services": [],
        "risk_level": "UNKNOWN",
    }

    # Check for launcher icon
    dump = vm_orchestrator._run_adb(
        ["shell", "pm", "dump", package_name],
        device=device, timeout=10
    )
    if dump["success"]:
        dump_text = dump["stdout"]
        info["has_launcher_icon"] = "category.LAUNCHER" in dump_text
        info["is_hidden"] = not info["has_launcher_icon"]

        # Extract permissions
        perm_section = False
        for line in dump_text.split("\n"):
            line = line.strip()
            if "requested permissions:" in line.lower():
                perm_section = True
                continue
            if perm_section and line.startswith("android.permission."):
                info["permissions"].append(line)
            elif perm_section and not line.startswith("android.permission") and line:
                perm_section = False

        # Extract services
        for line in dump_text.split("\n"):
            if "ServiceInfo{" in line:
                svc_match = re.search(r"ServiceInfo\{[^ ]+ ([^}]+)\}", line)
                if svc_match:
                    info["services"].append(svc_match.group(1))

    # Check for install path
    path_result = vm_orchestrator._run_adb(
        ["shell", "pm", "path", package_name],
        device=device, timeout=5
    )
    if path_result["success"]:
        info["install_path"] = path_result["stdout"].strip().replace("package:", "")

    # Check if running
    ps_result = vm_orchestrator._run_adb(
        ["shell", "ps", "-A"],
        device=device, timeout=5
    )
    if ps_result["success"]:
        info["is_running"] = package_name in ps_result["stdout"]

    # Determine risk level
    if info["is_hidden"] and info["is_running"]:
        info["risk_level"] = "CRITICAL"
    elif info["is_hidden"]:
        info["risk_level"] = "HIGH"
    elif info["is_running"]:
        info["risk_level"] = "MEDIUM"
    else:
        info["risk_level"] = "LOW"

    return info


def _get_package_network_connections(device: str, package_name: str) -> List[Dict[str, Any]]:
    """Get network connections for a specific package by its UID."""
    connections = []

    # Get UID for the package
    uid_result = vm_orchestrator._run_adb(
        ["shell", "dumpsys", "package", package_name],
        device=device, timeout=10
    )
    uid = None
    if uid_result["success"]:
        for line in uid_result["stdout"].split("\n"):
            if "userId=" in line:
                uid_match = re.search(r"userId=(\d+)", line)
                if uid_match:
                    uid = uid_match.group(1)
                    break

    if not uid:
        return connections

    # Check active connections from proc/net
    for proto_file in ["/proc/net/tcp", "/proc/net/tcp6"]:
        net_result = vm_orchestrator._run_adb(
            ["shell", "cat", proto_file],
            device=device, timeout=5
        )
        if net_result["success"]:
            for line in net_result["stdout"].split("\n")[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 8:
                    line_uid = parts[7] if len(parts) > 7 else ""
                    if line_uid == uid:
                        # Parse remote address
                        remote = parts[2] if len(parts) > 2 else ""
                        if ":" in remote:
                            hex_ip, hex_port = remote.split(":")
                            try:
                                ip_int = int(hex_ip, 16)
                                ip = f"{ip_int & 0xFF}.{(ip_int >> 8) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 24) & 0xFF}"
                                port = int(hex_port, 16)
                                if ip != "0.0.0.0" and ip != "127.0.0.1":
                                    connections.append({
                                        "destination": ip,
                                        "ip": ip,
                                        "port": str(port),
                                        "protocol": "TCP",
                                        "direction": "OUTBOUND",
                                        "source": "child_apk_network",
                                        "child_package": package_name,
                                    })
                            except ValueError:
                                pass

    return connections


# ── Root Detection ──────────────────────────────────────────────────

def _check_root_access(device: str) -> bool:
    """Check if the device has root (su) access."""
    result = vm_orchestrator._run_adb(
        ["shell", "su", "-c", "id"],
        device=device, timeout=5
    )
    return result["success"] and "uid=0" in result.get("stdout", "")


# ── Logcat Monitoring Thread ────────────────────────────────────────

def _get_app_pid(device: str, package_name: str) -> Optional[str]:
    """Get the PID of a running app."""
    if not package_name:
        return None
    result = vm_orchestrator._run_adb(
        ["shell", "pidof", package_name],
        device=device, timeout=5
    )
    if result["success"] and result["stdout"].strip():
        return result["stdout"].strip().split()[0]
    return None


# System-level logcat tags that reveal app behavior even when
# the package name is not in the line text.
_SYSTEM_EVENT_TAGS = {
    "ActivityManager": "activity",
    "ActivityTaskManager": "activity",
    "PackageManager": "dropper",
    "NetworkMonitor": "network",
    "ConnectivityService": "network",
    "NetworkStats": "network",
    "TrafficStats": "network",
    "ContentResolver": "data_exfil",
    "PermissionMonitor": "surveillance",
    "WindowManager": "data_exfil",
    "InputDispatcher": "general",
    "WebViewFactory": "network",
    "chromium": "network",
    "cr_": "network",
    "NativeCrypto": "crypto",
    "SSLUtils": "crypto",
    "TelephonyManager": "surveillance",
    "LocationManagerService": "surveillance",
    "GnssLocationProvider": "surveillance",
    "CameraService": "surveillance",
    "AudioFlinger": "surveillance",
    "MediaRecorder": "surveillance",
    "ClipboardService": "data_exfil",
    "NotificationService": "surveillance",
}


def _logcat_monitor_thread(session: Dict[str, Any]):
    """
    Background thread that monitors logcat comprehensively.
    Uses THREE strategies simultaneously:
      1) PID-filtered logcat to capture ALL app output
      2) System-level event monitoring (ActivityManager, network, etc.)
      3) Broad keyword matching on the full logcat stream
    """
    device = session["device_serial"]
    package_name = _clean_package_name(session.get("target_package", ""))

    # Clear logcat before starting
    vm_orchestrator._run_adb(["logcat", "-c"], device=device, timeout=5)

    adb = vm_orchestrator._find_adb()
    if not adb:
        return

    # Resolve the app's PID with retry (app may still be launching)
    app_pid = _get_app_pid(device, package_name)
    if not app_pid:
        for _ in range(5):
            time.sleep(1)
            app_pid = _get_app_pid(device, package_name)
            if app_pid:
                break

    if app_pid:
        logger.info(f"[Pentest] Target app PID: {app_pid} for {package_name}")
    else:
        logger.warning(f"[Pentest] Could not resolve initial PID for {package_name}")

    # Run logcat with threadtime format (includes PID/TID)
    cmd = [adb, "-s", device, "logcat", "-v", "threadtime"]
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace"
        )
        session["_logcat_proc"] = proc
        seen_event_keys = set()
        event_count = {"total": 0}
        last_pid_check = time.time()
        child_pids = set()

        while session["status"] == "monitoring" and proc.poll() is None:
            line = proc.stdout.readline()
            if not line:
                continue

            line = line.strip()
            if not line or line.startswith("-----"):
                continue

            # Re-check PID frequently (every 5s if not resolved, every 12s if resolved)
            now = time.time()
            pid_interval = 5 if not app_pid else 12
            if now - last_pid_check > pid_interval:
                new_pid = _get_app_pid(device, package_name)
                if new_pid and new_pid != app_pid:
                    logger.info(f"[Pentest] App PID changed: {app_pid} -> {new_pid}")
                    app_pid = new_pid
                # Also resolve child package PIDs
                for c in session.get("child_apks_detected", []):
                    cp = c.get("package_name")
                    if cp:
                        cpid = _get_app_pid(device, cp)
                        if cpid:
                            child_pids.add(cpid)
                last_pid_check = now

            # ── Strategy 1: Detect package installations (multiple methods) ──
            # Method A: PACKAGE_ADDED / PACKAGE_REPLACED broadcast
            if any(kw in line for kw in ["PACKAGE_ADDED", "PACKAGE_INSTALL", "PACKAGE_REPLACED",
                                          "package_verified", "commitSession", "installExisting"]):
                pkg_match = re.search(r"package:([^\s,}]+)", line)
                if not pkg_match:
                    # Try alternate format: "packageName=com.xxx.yyy"
                    pkg_match = re.search(r"packageName=([^\s,}]+)", line)
                if not pkg_match:
                    # Try: installed com.xxx.yyy
                    pkg_match = re.search(r"install(?:ed|ing)\s+([a-zA-Z][a-zA-Z0-9_.]+)", line)
                if pkg_match:
                    raw_child = pkg_match.group(1)
                    child_pkg = _clean_package_name(raw_child)
                    if child_pkg and child_pkg != package_name and child_pkg != PCAPDROID_PACKAGE:
                        already = any(c.get("package_name") == child_pkg
                                      for c in session["child_apks_detected"])
                        if not already:
                            logger.info(f"[Pentest] Logcat broadcast detected new package install: {child_pkg}")
                            pkg_info = _analyze_new_package(device, child_pkg)
                            session["child_apks_detected"].append(pkg_info)
                            session["events"].append({
                                "id": str(uuid4()),
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "api_call": f"CHILD_APK_INSTALLED: {child_pkg}",
                                "description": f"Dropper detected: silently installed child package '{child_pkg}'" +
                                               (" [HIDDEN APP]" if pkg_info.get("is_hidden") else ""),
                                "category": "dropper",
                                "risk_level": "CRITICAL",
                                "class_name": "android.content.pm.PackageInstaller",
                                "source": "manual_pentest",
                            })

                            # Immediately capture child APK network connections
                            child_net = _get_package_network_connections(device, child_pkg)
                            if child_net:
                                session["network_activity"].extend(child_net)

            # Method B: Detect if our target app is calling PackageInstaller
            if package_name and package_name in line:
                if any(kw in line.lower() for kw in ["packageinstaller", "installpackage",
                                                      "install_package", "session.commit"]):
                    session["events"].append({
                        "id": str(uuid4()),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "api_call": "Package Install Attempt",
                        "description": f"Target app is attempting to install a package: {msg[:200] if msg else line[:200]}",
                        "category": "dropper",
                        "risk_level": "CRITICAL",
                        "class_name": package_name,
                        "source": "manual_pentest",
                    })

            # Parse the threadtime format:
            # "MM-DD HH:MM:SS.sss  PID  TID LEVEL TAG: message"
            parsed = _parse_logcat_line(line)
            if not parsed:
                continue

            line_pid = parsed["pid"]
            tag = parsed["tag"]
            msg = parsed["message"]
            level = parsed["level"]

            # Skip excessively noisy verbose lines unless from app PID
            if level in ("V",) and tag not in _SYSTEM_EVENT_TAGS and line_pid != app_pid:
                continue

            # ── Strategy 2: Capture ALL lines from the app's PID ──
            is_app_line = False
            if app_pid and line_pid == app_pid:
                is_app_line = True
            elif line_pid in child_pids:
                is_app_line = True
            # Also catch if the package name appears anywhere in the line
            elif package_name and package_name in line:
                is_app_line = True
            # Also match child package lines
            child_pkgs = [c.get("package_name") for c in session.get("child_apks_detected", [])]
            for cp in child_pkgs:
                if cp and cp in line:
                    is_app_line = True
                    break

            # ── Strategy 3: System-level events about our app ──
            is_system_event = False
            system_category = "general"
            if tag in _SYSTEM_EVENT_TAGS:
                # Only capture if it mentions our app or is broadly relevant
                if (package_name and package_name in msg) or is_app_line:
                    is_system_event = True
                    system_category = _SYSTEM_EVENT_TAGS[tag]

            # If this line is from the app or about the app, process it
            if is_app_line or is_system_event:
                _classify_and_emit_event(
                    line, tag, msg, level,
                    package_name, session, seen_event_keys, event_count,
                    is_system=is_system_event,
                    system_category=system_category
                )

    except Exception as e:
        logger.error(f"Logcat monitor error: {e}")
    finally:
        if proc and proc.poll() is None:
            proc.terminate()


def _parse_logcat_line(line: str) -> Optional[Dict[str, str]]:
    """Parse a logcat threadtime line into components."""
    # Format: "MM-DD HH:MM:SS.sss  PID  TID LEVEL TAG: message"
    match = re.match(
        r"(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+"
        r"(\d+)\s+(\d+)\s+([VDIWEF])\s+"
        r"([^:]+):\s*(.*)",
        line
    )
    if match:
        return {
            "timestamp": match.group(1),
            "pid": match.group(2),
            "tid": match.group(3),
            "level": match.group(4),
            "tag": match.group(5).strip(),
            "message": match.group(6).strip(),
        }
    return None


# ── Comprehensive Event Classification ──────────────────────────────

# ── Comprehensive Event Classification ──────────────────────────────

# Categorized keyword rules: (keywords, api_call, category, risk_level)
_EVENT_RULES = [
    # Financial & Credential Activity (UPI, PIN, OTP, Banking, Passwords, Payment)
    # Short keywords (<=4 chars) are prefixed with r: to trigger word-boundary regex matching
    (["r:upi", "r:pin", "r:otp", "r:mpin", "r:vpa", "bhim", "npci", "phonepe", "gpay",
      "paytm", "r:bank", "wallet", "creditcard", "debitcard", "r:cvv", "payment",
      "account_number", "r:ifsc", "beneficiary", "razorpay", "billdesk", "citrus"],
     "Financial/Credential Interaction", "data_exfil", "HIGH"),
    # User UI Actions & Input
    (["onclick", "ontouch", "motionevent", "keyevent", "dispatchkeyevent",
      "textchanged", "oneditoraction", "submit", "button_click", "inputmethod",
      "keyboard", "focuschange", "onkey"],
     "User UI Interaction", "activity", "LOW"),
    # Network - HTTP/HTTPS/WebSocket
    (["httpurlconnection", "okhttp", "urlconnection", "httpsclient",
      "retrofit", "volley", "xmlhttprequest", "webviewclient",
      "http://", "https://", "shouldoverrideurlloading",
      "onpagestarted", "onpagefinished", "loadurl"],
     "Network/HTTP Request", "network", "MEDIUM"),
    # Network - Socket/TCP
    (["socket", "connect(", "serversocket", "datagramsocket",
      "sslsocket", "ssl handshake", "tcp_connection"],
     "Socket Connection", "network", "MEDIUM"),
    # SMS
    (["smsmanager", "sendtextmessage", "sms_received", "sms_sent",
      "sendmultimessage", "content://sms", "telephony.sms"],
     "SMS Activity", "sms", "CRITICAL"),
    # Telephony / Calls
    (["telephonymanager", "getdeviceid", "getsubscriberid", "getline1number",
      "getimei", "phone_state", "call_log", "action_call", "getnetworkoperator",
      "simoperator", "networktype"],
     "Telephony/Device ID Access", "surveillance", "HIGH"),
    # Accessibility / Overlay
    (["accessibilityservice", "draw_over", "type_application_overlay",
      "system_alert_window", "onserviceconnected"],
     "Accessibility/Overlay Abuse", "data_exfil", "CRITICAL"),
    # Crypto / Encryption / SSL
    (["cipher", "secretkey", "javax.crypto", "encrypt", "decrypt",
      "messagedigest", "keygenparameterspec", "bouncycastle",
      "x509certificate", "trustmanager", "r:ssl", "r:tls"],
     "Cryptographic Operation", "crypto", "MEDIUM"),
    # Location / GPS
    (["locationmanager", "getlastknownlocation", "fused_provider",
      "requestlocationupdates", "geocoder", "fine_location",
      "coarse_location", "gnsslocationprovider", "gps_enabled"],
     "Location Access", "surveillance", "HIGH"),
    # Camera / Microphone
    (["camera.open", "cameramanager", "mediarecorder", "audiorecord",
      "record_audio", "camera2", "takepicture", "cameradevice",
      "audioflinger", "microphone"],
     "Camera/Microphone Access", "surveillance", "CRITICAL"),
    # Contacts / Calendar / Call Log
    (["contactscontract", "content://contacts", "content://call_log",
      "content://calendar", "read_contacts", "write_contacts",
      "content://com.android.contacts"],
     "Contacts/Calendar Access", "data_exfil", "HIGH"),
    # Device Admin / Privilege Escalation
    (["deviceadminreceiver", "devicepolicymanager", "bind_device_admin",
      "requestadmin", "locknow", "wipedata", "resetpassword"],
     "Device Admin Abuse", "privilege_escalation", "CRITICAL"),
    # Dynamic Code Loading
    (["dexclassloader", "pathclassloader", "inmemorydexclassloader",
      "dalvik.system.dex", "defineclass",
      "system.loadlibrary", "system.load(", "runtime.exec"],
     "Dynamic Code Loading", "evasion", "CRITICAL"),
    # Reflection
    (["java.lang.reflect", "getdeclaredmethod", "setaccessible",
      "class.forname"],
     "Reflection/API Hiding", "evasion", "HIGH"),
    # File System
    (["openfileinput", "openfileoutput", "getexternalfilesdir",
      "sharedpreferences", "contentresolver.query",
      "content://media", "content://downloads"],
     "File System Access", "data_exfil", "MEDIUM"),
    # Clipboard
    (["clipboardmanager", "getprimaryclip", "setprimaryclip"],
     "Clipboard Access", "data_exfil", "HIGH"),
    # Notification Listener
    (["notificationlistenerservice", "bind_notification_listener",
      "getactivenotifications"],
     "Notification Listener", "surveillance", "CRITICAL"),
    # Battery/Power
    (["request_ignore_battery_optimizations", "wakelock",
      "action_request_ignore_battery_optimizations"],
     "Battery Optimization Bypass", "persistence", "MEDIUM"),
    # Boot Persistence
    (["boot_completed", "quickboot_poweron", "receive_boot_completed"],
     "Boot Persistence", "persistence", "HIGH"),
    # WebView specific
    (["webview", "webchromeclient", "javascriptinterface", "evaluatejavascript",
      "addjavascriptinterface", "webkit"],
     "WebView Activity", "network", "MEDIUM"),
    # Database/Storage
    (["sqlite", "database", "cursor.query", "contentvalues", "insert into",
      "select from", "rawquery"],
     "Database Operation", "data_exfil", "LOW"),
    # Intent/IPC
    (["startactivity", "startservice", "sendbroadcast", "bindservice",
      "intent.action", "contentprovider"],
     "Inter-Process Communication", "general", "LOW"),
]

# Tags whose output should be captured more aggressively from the app's PID
_APP_IMPORTANT_TAGS = {
    "System.out", "System.err", "AndroidRuntime", "dalvikvm",
    "art", "ActivityThread", "WebViewFactory",
}


def _classify_and_emit_event(
    full_line: str, tag: str, msg: str, level: str,
    package_name: str, session: Dict[str, Any],
    seen_keys: set, event_count: Dict[str, int],
    is_system: bool = False, system_category: str = "general",
):
    """Classify a logcat line and emit it as a structured event."""
    # Match keywords against the MESSAGE content only (not the full line)
    # This prevents the package name (which is in every logcat line) from triggering
    # false positives. E.g., package "net.noce.vihupi" would wrongly match keyword "upi".
    msg_lower = msg.lower()

    # Skip our own ADB monitoring commands — they always contain the package name
    # and would trigger false positives
    if tag == "ADB_SERVICES" and ("pidof" in msg_lower or "dumpsys" in msg_lower):
        return

    # Skip Pinning/dexopt system messages that falsely match "pin"
    if "pinning" in msg_lower and ("dexopt" in msg_lower or "optimized" in msg_lower):
        return

    # ── Check keyword rules (match against message content only) ──
    for keywords, api_call, category, risk_level in _EVENT_RULES:
        matched = False
        for kw in keywords:
            if kw.startswith("r:"):
                # Letter-boundary match for short keywords
                # Prevents "vihupi" matching "upi" but allows "upi_id", "upi.pin"
                # Only requires non-letter chars (or start/end) around the keyword
                pattern = r'(?<![a-zA-Z])' + re.escape(kw[2:]) + r'(?![a-zA-Z])'
                if re.search(pattern, msg_lower):
                    matched = True
                    break
            else:
                # Normal substring match
                if kw in msg_lower:
                    matched = True
                    break

        if matched:
            dedup_key = f"{package_name}:{api_call}"
            count = sum(1 for k in seen_keys if k.startswith(dedup_key))
            if count >= 5:  # Max 5 of each type to avoid timeline spam
                return
            seen_keys.add(f"{dedup_key}:{count}")

            session["events"].append({
                "id": str(uuid4()),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "api_call": api_call,
                "description": msg[:300] if msg else full_line[:300],
                "category": category,
                "risk_level": risk_level,
                "class_name": package_name,
                "source": "manual_pentest",
                "log_tag": tag,
                "log_level": level,
            })
            event_count["total"] += 1
            return

    # ── System-level activity events (ActivityManager) ──
    if tag in ("ActivityManager", "ActivityTaskManager"):
        # Detect activity transitions: "START", "Displayed", "Destroying"
        if any(kw in msg for kw in ["START", "Displayed", "Destroying",
                                      "ANR in", "Force finishing",
                                      "Process", "Killing"]):
            # Extract activity name if present
            act_match = re.search(r"([\w.]+/[\w.]+)", msg)
            activity_name = act_match.group(1) if act_match else ""

            dedup_key = f"activity:{msg[:60]}"
            if dedup_key in seen_keys:
                return
            seen_keys.add(dedup_key)

            session["events"].append({
                "id": str(uuid4()),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "api_call": f"Activity: {activity_name or tag}",
                "description": msg[:300],
                "category": "activity",
                "risk_level": "LOW",
                "class_name": package_name,
                "source": "manual_pentest",
                "log_tag": tag,
                "log_level": level,
            })
            event_count["total"] += 1
            return

    # ── Error/Warning/Exception detection (always capture) ──
    if level in ("E", "W") or "exception" in msg_lower or "error" in msg_lower:
        if tag in ("AndroidRuntime", "System.err") or "crash" in msg_lower:
            dedup_key = f"error:{tag}:{msg[:40]}"
            if dedup_key in seen_keys:
                return
            seen_keys.add(dedup_key)

            session["events"].append({
                "id": str(uuid4()),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "api_call": f"Error/Crash: {tag}",
                "description": msg[:300],
                "category": "error",
                "risk_level": "MEDIUM",
                "class_name": package_name,
                "source": "manual_pentest",
                "log_tag": tag,
                "log_level": level,
            })
            event_count["total"] += 1
            return

    # ── Catch-all: Capture all meaningful app log lines ──
    # Skip noisy framework render lines
    skip_tags = {"ViewRootImpl", "RenderThread",
                 "OpenGLRenderer", "hwui", "Looper",
                 "MessageQueue", "ThreadedRenderer", "Surface",
                 "SurfaceView", "TextureView", "eglCodecCommon",
                 "gralloc", "EGL_emulation", "mali", "ion",
                 "libEGL", "chatty"}
    if tag in skip_tags:
        return

    # Skip very short or empty messages
    if len(msg) < 4:
        return

    # Cap total general events to avoid flooding (500 events allowed)
    general_count = sum(1 for k in seen_keys if k.startswith("general:"))
    if general_count >= 500:
        return

    dedup_key = f"general:{tag}:{msg[:50]}"
    if dedup_key in seen_keys:
        return
    seen_keys.add(dedup_key)

    # Determine risk level based on log level
    risk = "LOW"
    if level == "E":
        risk = "MEDIUM"
    elif level == "W":
        risk = "LOW"

    session["events"].append({
        "id": str(uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "api_call": f"App Log [{tag}]",
        "description": msg[:300],
        "category": system_category if is_system else "general",
        "risk_level": risk,
        "class_name": package_name,
        "source": "manual_pentest",
        "log_tag": tag,
        "log_level": level,
    })
    event_count["total"] += 1


# ── Activity & Screen Tracking Thread ────────────────────────────────

def _activity_track_thread(session: Dict[str, Any]):
    """
    Background thread that polls the device for running activities,
    focused windows/dialogs (UPI PIN, passwords, permissions, payment),
    and services of the target app.
    """
    device = session["device_serial"]
    package_name = _clean_package_name(session.get("target_package", ""))
    if not package_name:
        return

    last_activity = ""
    last_focus = ""
    seen_services = set()

    while session["status"] == "monitoring":
        try:
            # 1. Get current top resumed activity
            result = vm_orchestrator._run_adb(
                ["shell", "dumpsys", "activity", "activities"],
                device=device, timeout=5
            )
            if result["success"]:
                for line in result["stdout"].split("\n"):
                    if "mResumedActivity" in line or "topResumedActivity" in line:
                        act_match = re.search(r"([\w.]+/[\w.]+)", line)
                        if act_match:
                            current_activity = act_match.group(1)
                            if current_activity != last_activity:
                                lower_act = current_activity.lower()
                                risk = "LOW"
                                category = "activity"
                                api_call = f"Screen: {current_activity}"
                                desc = f"User navigated to screen: {current_activity}"

                                if any(k in lower_act for k in ["upi", "pin", "payment", "bank", "pay", "checkout", "auth", "login"]):
                                    risk = "HIGH"
                                    category = "data_exfil"
                                    api_call = f"Financial/Auth Screen: {current_activity}"
                                    desc = f"App opened financial or authentication screen: {current_activity}"

                                session["events"].append({
                                    "id": str(uuid4()),
                                    "timestamp": datetime.now(timezone.utc).isoformat(),
                                    "api_call": api_call,
                                    "description": desc,
                                    "category": category,
                                    "risk_level": risk,
                                    "class_name": package_name,
                                    "source": "manual_pentest",
                                })
                                last_activity = current_activity
                        break

            # 2. Get currently focused window / dialog (catches UPI PIN dialogs, keyboards, permissions)
            focus_result = vm_orchestrator._run_adb(
                ["shell", "dumpsys", "window"],
                device=device, timeout=5
            )
            if focus_result["success"]:
                for line in focus_result["stdout"].split("\n"):
                    if "mCurrentFocus" in line or "mFocusedApp" in line:
                        focus_match = re.search(r"\{[^\}]+\s+([^\}]+)\}", line)
                        if focus_match:
                            curr_focus = focus_match.group(1).strip()
                            if curr_focus and curr_focus != last_focus and curr_focus != last_activity:
                                lower_focus = curr_focus.lower()
                                if package_name in curr_focus or any(k in lower_focus for k in ["upi", "pin", "auth", "permission", "dialog", "overlay"]):
                                    risk = "MEDIUM"
                                    api_call = f"UI Focus: {curr_focus}"
                                    category = "activity"
                                    if any(k in lower_focus for k in ["upi", "pin", "otp", "password"]):
                                        risk = "HIGH"
                                        category = "data_exfil"
                                        api_call = f"Credential/PIN Dialog: {curr_focus}"

                                    session["events"].append({
                                        "id": str(uuid4()),
                                        "timestamp": datetime.now(timezone.utc).isoformat(),
                                        "api_call": api_call,
                                        "description": f"User interaction with UI component: {curr_focus}",
                                        "category": category,
                                        "risk_level": risk,
                                        "class_name": package_name,
                                        "source": "manual_pentest",
                                    })
                                    last_focus = curr_focus
                        break

            # 3. Get running services for the package
            svc_result = vm_orchestrator._run_adb(
                ["shell", "dumpsys", "activity", "services", package_name],
                device=device, timeout=5
            )
            if svc_result["success"]:
                for line in svc_result["stdout"].split("\n"):
                    if "ServiceRecord" in line and package_name in line:
                        svc_match = re.search(r"([\w.]+/[\w.]+Service[\w.]*)", line)
                        if svc_match:
                            svc_name = svc_match.group(1)
                            if svc_name not in seen_services:
                                seen_services.add(svc_name)
                                session["events"].append({
                                    "id": str(uuid4()),
                                    "timestamp": datetime.now(timezone.utc).isoformat(),
                                    "api_call": f"Background Service: {svc_name}",
                                    "description": f"App is running background service: {svc_name}",
                                    "category": "persistence",
                                    "risk_level": "MEDIUM",
                                    "class_name": package_name,
                                    "source": "manual_pentest",
                                })

        except Exception as e:
            logger.debug(f"Activity track error: {e}")

        time.sleep(3)  # Poll every 3 seconds for responsive tracking


# ── Package Polling Thread (Real-Time Child APK Detection) ──────────

def _package_poll_thread(session: Dict[str, Any]):
    """
    Background thread that polls installed packages in real-time.
    Detects when the parent APK silently drops/installs a child APK.
    """
    device = session["device_serial"]
    target_pkg = _clean_package_name(session.get("target_package", ""))

    while session["status"] == "monitoring":
        try:
            current_packages = _snapshot_packages(device)
            known_packages = session.get("packages_before", set())
            new_pkgs = current_packages - known_packages

            for pkg in new_pkgs:
                clean_pkg = _clean_package_name(pkg)
                if not clean_pkg:
                    continue
                if clean_pkg == target_pkg or clean_pkg == PCAPDROID_PACKAGE:
                    continue

                already = any(c.get("package_name") == clean_pkg for c in session.get("child_apks_detected", []))
                if not already:
                    logger.info(f"[Pentest] Real-time child APK detected on device: {clean_pkg}")
                    pkg_info = _analyze_new_package(device, clean_pkg)
                    session["child_apks_detected"].append(pkg_info)

                    desc = f"Child/Dropper APK detected: {clean_pkg}"
                    if pkg_info.get("is_hidden"):
                        desc += " (HIDDEN — No launcher icon!)"
                    if pkg_info.get("is_running"):
                        desc += " (ACTIVE — Running in background!)"

                    session["events"].append({
                        "id": str(uuid4()),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "api_call": f"CHILD_APK_DETECTED: {clean_pkg}",
                        "description": desc,
                        "category": "dropper",
                        "risk_level": "CRITICAL" if pkg_info.get("is_hidden") else "HIGH",
                        "class_name": "android.content.pm.PackageInstaller",
                        "source": "manual_pentest",
                    })

                    # Also collect child network connections immediately
                    child_net = _get_package_network_connections(device, clean_pkg)
                    if child_net:
                        session["network_activity"].extend(child_net)

            # Also continuously monitor network connections from ALL detected child APKs
            # (some child APKs start making connections in background after a delay)
            for child_info in session.get("child_apks_detected", []):
                child_pkg = child_info.get("package_name", "")
                if not child_pkg:
                    continue
                child_net = _get_package_network_connections(device, child_pkg)
                for cn in child_net:
                    # Check if this specific connection is already known
                    existing_key = f"{cn.get('ip', '')}:{cn.get('port', '')}"
                    already_known = any(
                        f"{n.get('ip', '')}:{n.get('port', '')}" == existing_key
                        for n in session["network_activity"]
                    )
                    if not already_known:
                        cn["source"] = "child_apk_network"
                        session["network_activity"].append(cn)

                        # Also emit as timeline event
                        session["events"].append({
                            "id": str(uuid4()),
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "api_call": f"Child APK Network: {cn.get('destination', cn.get('ip', ''))}:{cn.get('port', '')}",
                            "description": f"Child APK '{child_pkg}' connecting to {cn.get('destination', cn.get('ip', ''))} port {cn.get('port', '')}",
                            "category": "network",
                            "risk_level": "HIGH",
                            "class_name": child_pkg,
                            "source": "manual_pentest",
                        })

        except Exception as e:
            logger.debug(f"Package poll error: {e}")

        time.sleep(3)  # Poll every 3 seconds for faster child APK detection


# ── Network Monitoring Thread (Enhanced) ─────────────────────────────

def _resolve_hostname(ip: str) -> str:
    """Attempt reverse DNS lookup for an IP address. Returns hostname or empty string."""
    import socket as _socket
    try:
        info = _socket.gethostbyaddr(ip)
        if info and info[0]:
            return info[0]
    except Exception:
        pass
    return ""


def _parse_proc_net(raw: str, protocol: str = "TCP") -> list:
    """Parse /proc/net/tcp, tcp6, or udp output into connection dicts."""
    connections = []
    for line in raw.strip().split("\n")[1:]:  # Skip header
        parts = line.split()
        if len(parts) < 4:
            continue
        try:
            remote = parts[2]
            hex_ip, hex_port = remote.split(":")
            port = int(hex_port, 16)

            if len(hex_ip) == 8:
                # IPv4
                ip_int = int(hex_ip, 16)
                ip = f"{ip_int & 0xFF}.{(ip_int >> 8) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 24) & 0xFF}"
            elif len(hex_ip) == 32:
                # IPv6 — extract last 4 bytes as IPv4 if it's a mapped address
                if hex_ip[:24] == "0000000000000000FFFF0000" or hex_ip[:24] == "0000000000000000ffff0000":
                    v4_hex = hex_ip[24:]
                    ip_int = int(v4_hex, 16)
                    ip = f"{ip_int & 0xFF}.{(ip_int >> 8) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 24) & 0xFF}"
                else:
                    # Full IPv6 — format as hex groups
                    ip = ":".join(hex_ip[i:i+4] for i in range(0, 32, 4))
            else:
                continue

            # Skip loopback, unspecified, and private ranges
            if ip in ("0.0.0.0", "127.0.0.1", "::1", "0000:0000:0000:0000:0000:0000:0000:0001"):
                continue
            if port == 0:
                continue

            # Get UID if available (field index 7 for tcp, udp)
            uid = parts[7] if len(parts) > 7 else ""

            connections.append({
                "ip": ip,
                "port": port,
                "protocol": protocol,
                "uid": uid,
            })
        except (ValueError, IndexError):
            continue
    return connections


def _get_app_uid(device: str, package_name: str) -> str:
    """Get the Linux UID for a package on the device."""
    result = vm_orchestrator._run_adb(
        ["shell", "dumpsys", "package", package_name],
        device=device, timeout=10
    )
    if result["success"]:
        for line in result["stdout"].split("\n"):
            if "userId=" in line:
                uid_match = re.search(r"userId=(\d+)", line)
                if uid_match:
                    return uid_match.group(1)
    return ""


def _get_uid_traffic_bytes(device: str, uid: str) -> Dict[str, int]:
    """Get traffic bytes for a specific UID from /proc/uid_stat/<uid>/."""
    result = {"tcp_snd": 0, "tcp_rcv": 0}
    for stat_file, key in [("tcp_snd", "tcp_snd"), ("tcp_rcv", "tcp_rcv")]:
        r = vm_orchestrator._run_adb(
            ["shell", "cat", f"/proc/uid_stat/{uid}/{stat_file}"],
            device=device, timeout=3
        )
        if r["success"] and r["stdout"].strip().isdigit():
            result[key] = int(r["stdout"].strip())
    return result


def _network_monitor_thread(session: Dict[str, Any]):
    """
    Enhanced network monitoring thread that polls TCP, TCP6, and UDP
    connections, resolves hostnames, tracks data volume, and emits
    timeline events for the behavior timeline.
    """
    device = session["device_serial"]
    package_name = _clean_package_name(session.get("target_package", ""))
    seen_connections: Dict[str, Dict[str, Any]] = {}  # key -> connection record
    app_uid = _get_app_uid(device, package_name) if package_name else ""

    # Track initial traffic baseline
    baseline_bytes = {"tcp_snd": 0, "tcp_rcv": 0}
    if app_uid:
        baseline_bytes = _get_uid_traffic_bytes(device, app_uid)

    # Track child APK UIDs for attribution
    child_uid_map: Dict[str, str] = {}  # uid -> package_name
    target_uid = app_uid  # UID of the parent/target APK

    poll_count = 0

    while session["status"] == "monitoring":
        try:
            all_connections = []

            # Poll /proc/net/tcp
            tcp_result = vm_orchestrator._run_adb(
                ["shell", "cat", "/proc/net/tcp"],
                device=device, timeout=5
            )
            if tcp_result["success"]:
                all_connections.extend(_parse_proc_net(tcp_result["stdout"], "TCP"))

            # Poll /proc/net/tcp6
            tcp6_result = vm_orchestrator._run_adb(
                ["shell", "cat", "/proc/net/tcp6"],
                device=device, timeout=5
            )
            if tcp6_result["success"]:
                all_connections.extend(_parse_proc_net(tcp6_result["stdout"], "TCP"))

            # Poll /proc/net/udp
            udp_result = vm_orchestrator._run_adb(
                ["shell", "cat", "/proc/net/udp"],
                device=device, timeout=5
            )
            if udp_result["success"]:
                all_connections.extend(_parse_proc_net(udp_result["stdout"], "UDP"))

            # Poll /proc/net/udp6
            udp6_result = vm_orchestrator._run_adb(
                ["shell", "cat", "/proc/net/udp6"],
                device=device, timeout=5
            )
            if udp6_result["success"]:
                all_connections.extend(_parse_proc_net(udp6_result["stdout"], "UDP"))

            # Build child UID map from detected child packages
            if poll_count % 6 == 0:  # Refresh every ~30s
                for child in session.get("child_apks", []):
                    child_pkg = child.get("package_name", "")
                    if child_pkg and child_pkg not in [v for v in child_uid_map.values()]:
                        child_uid = _get_app_uid(device, child_pkg)
                        if child_uid:
                            child_uid_map[child_uid] = child_pkg

            for conn in all_connections:
                ip = conn["ip"]
                port = conn["port"]
                protocol = conn["protocol"]
                conn_uid = conn.get("uid", "")

                # Skip common local/Google IPs to reduce noise
                if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("169.254."):
                    continue

                # Determine which package owns this connection
                source_package = package_name  # default to parent
                apk_type = "parent"
                if conn_uid and conn_uid == target_uid:
                    source_package = package_name
                    apk_type = "parent"
                elif conn_uid and conn_uid in child_uid_map:
                    source_package = child_uid_map[conn_uid]
                    apk_type = "child"
                elif conn_uid and int(conn_uid) < 10000:
                    source_package = f"system (uid:{conn_uid})"
                    apk_type = "system"

                key = f"{ip}:{port}:{protocol}"
                if key not in seen_connections:
                    # New connection — resolve hostname and emit
                    hostname = _resolve_hostname(ip)
                    now_ts = datetime.now(timezone.utc).isoformat()

                    conn_record = {
                        "destination": hostname or ip,
                        "hostname": hostname,
                        "ip": ip,
                        "port": str(port),
                        "protocol": protocol,
                        "direction": "OUTBOUND",
                        "first_seen": now_ts,
                        "bytes_sent": 0,
                        "bytes_received": 0,
                        "source": "manual_pentest_runtime",
                        "source_package": source_package,
                        "apk_type": apk_type,
                    }
                    seen_connections[key] = conn_record
                    session["network_activity"].append(conn_record)

                    # Also emit as a behavior timeline event
                    display_dest = hostname or ip
                    is_suspicious = not any(
                        ip.startswith(p) for p in [
                            "172.217.", "142.250.", "142.251.",
                            "216.58.", "8.8.", "1.1.1.", "1.0.0.",
                        ]
                    )
                    risk = "MEDIUM" if is_suspicious else "LOW"

                    apk_label = f"📦 {apk_type.capitalize()}" if apk_type != "parent" else "📱 Parent"
                    session["events"].append({
                        "id": str(uuid4()),
                        "timestamp": now_ts,
                        "api_call": f"Network Connection: {display_dest}:{port}",
                        "description": f"App connected to {display_dest} ({ip}) on port {port}/{protocol}",
                        "category": "network",
                        "risk_level": risk,
                        "class_name": source_package,
                        "source": "manual_pentest",
                        "source_package": source_package,
                        "apk_type": apk_type,
                        "apk_label": apk_label,
                        "log_tag": "NetworkMonitor",
                        "log_level": "I",
                    })

            # Periodically update traffic volume (every 3rd poll = ~15s)
            poll_count += 1
            if app_uid and poll_count % 3 == 0:
                current_bytes = _get_uid_traffic_bytes(device, app_uid)
                total_sent = max(0, current_bytes["tcp_snd"] - baseline_bytes["tcp_snd"])
                total_recv = max(0, current_bytes["tcp_rcv"] - baseline_bytes["tcp_rcv"])
                session["_app_traffic"] = {
                    "total_bytes_sent": total_sent,
                    "total_bytes_received": total_recv,
                }

                # Distribute evenly across connections (rough estimate)
                n_conns = len(seen_connections) or 1
                per_conn_sent = total_sent // n_conns
                per_conn_recv = total_recv // n_conns
                for rec in seen_connections.values():
                    rec["bytes_sent"] = per_conn_sent
                    rec["bytes_received"] = per_conn_recv

            # ── Fallback: Use 'dumpsys netstats' for per-UID traffic data ──
            # This works without root and provides traffic attribution
            if not all_connections and poll_count % 2 == 0:
                try:
                    netstats = vm_orchestrator._run_adb(
                        ["shell", "dumpsys", "netstats", "detail"],
                        device=device, timeout=10
                    )
                    if netstats["success"] and app_uid:
                        _parse_netstats_for_uid(
                            netstats["stdout"], app_uid, package_name, session
                        )
                except Exception:
                    pass

            # ── Fallback: Use 'netstat' command ──
            if not all_connections and poll_count % 3 == 0:
                try:
                    ns_result = vm_orchestrator._run_adb(
                        ["shell", "netstat", "-tunp"],
                        device=device, timeout=8
                    )
                    if ns_result["success"]:
                        _parse_netstat_output(
                            ns_result["stdout"], package_name, session, seen_connections
                        )
                except Exception:
                    pass

        except Exception as e:
            logger.debug(f"Network monitor error: {e}")

        time.sleep(5)  # Poll every 5 seconds


# ── Network Fallback Parsers ────────────────────────────────────────

def _parse_netstats_for_uid(output: str, app_uid: str, package_name: str, session: Dict):
    """Parse dumpsys netstats detail output to find traffic data for our app's UID."""
    try:
        lines = output.split("\n")
        in_uid_block = False
        total_rx = 0
        total_tx = 0

        for line in lines:
            line = line.strip()

            # Look for our UID's section
            if f"uid={app_uid}" in line:
                in_uid_block = True
                continue

            if in_uid_block:
                if line.startswith("uid=") or line.startswith("ident="):
                    in_uid_block = False
                    continue

                # Parse rxBytes and txBytes
                rx_match = re.search(r"rxBytes=(\d+)", line)
                tx_match = re.search(r"txBytes=(\d+)", line)
                if rx_match:
                    total_rx += int(rx_match.group(1))
                if tx_match:
                    total_tx += int(tx_match.group(1))

        if total_rx > 0 or total_tx > 0:
            session["_app_traffic"] = {
                "total_bytes_sent": total_tx,
                "total_bytes_received": total_rx,
            }
            logger.debug(f"[NetStats] UID {app_uid} traffic: TX={total_tx}, RX={total_rx}")
    except Exception as e:
        logger.debug(f"[NetStats] Parse error: {e}")


def _parse_netstat_output(output: str, package_name: str, session: Dict,
                          seen_connections: Dict):
    """Parse 'netstat -tunp' output to find active connections."""
    try:
        for line in output.strip().split("\n"):
            parts = line.split()
            if len(parts) < 5:
                continue

            # Format: Proto Recv-Q Send-Q LocalAddr ForeignAddr State PID/Program
            proto = parts[0].upper()
            if proto not in ("TCP", "UDP", "TCP6", "UDP6"):
                continue

            foreign = parts[4] if len(parts) > 4 else ""
            if ":" not in foreign:
                continue

            # Parse foreign address
            if foreign.startswith("::ffff:"):
                foreign = foreign[7:]

            parts_addr = foreign.rsplit(":", 1)
            if len(parts_addr) != 2:
                continue

            ip = parts_addr[0]
            try:
                port = int(parts_addr[1])
            except ValueError:
                continue

            # Skip local/loopback
            if ip in ("0.0.0.0", "127.0.0.1", "::1", "*", "::") or port == 0:
                continue
            if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("169.254."):
                continue

            # Check PID/program for our package
            pid_prog = parts[-1] if len(parts) > 6 else ""
            program = pid_prog.split("/")[-1] if "/" in pid_prog else ""

            key = f"{ip}:{port}:{proto}"
            if key not in seen_connections:
                hostname = _resolve_hostname(ip)
                now_ts = datetime.now(timezone.utc).isoformat()

                conn_record = {
                    "destination": hostname or ip,
                    "hostname": hostname,
                    "ip": ip,
                    "port": str(port),
                    "protocol": proto.replace("6", ""),
                    "direction": "OUTBOUND",
                    "first_seen": now_ts,
                    "bytes_sent": 0,
                    "bytes_received": 0,
                    "source": "netstat_capture",
                    "attributed_package": package_name or "unknown",
                    "program": program,
                }
                seen_connections[key] = conn_record
                session["network_activity"].append(conn_record)

                session["events"].append({
                    "id": str(uuid4()),
                    "timestamp": now_ts,
                    "api_call": f"Network: {hostname or ip}:{port}",
                    "description": f"Active connection to {hostname or ip} ({ip}) port {port}/{proto}",
                    "category": "network",
                    "risk_level": "MEDIUM",
                    "class_name": package_name,
                    "source": "manual_pentest",
                })
    except Exception as e:
        logger.debug(f"[Netstat] Parse error: {e}")


# ── PCAP Analysis ───────────────────────────────────────────────────

def _parse_pcap_file(pcap_path: str) -> Dict[str, Any]:
    """
    Parse a PCAP file to extract network traffic summary.
    Uses scapy if available, falls back to basic binary parsing.
    Returns dict with connections, dns_mappings, and traffic stats.
    """
    result = {
        "connections": [],        # List of {ip, port, protocol, hostname, packets, bytes, first_seen, last_seen}
        "dns_mappings": {},       # domain -> [ips]
        "total_packets": 0,
        "total_bytes": 0,
        "protocols": {},          # protocol -> packet_count
    }

    if not pcap_path or not os.path.exists(pcap_path):
        return result

    try:
        from scapy.all import rdpcap, IP, IPv6, TCP, UDP, DNS, DNSQR, DNSRR, conf
        # Suppress scapy warnings
        conf.verb = 0

        logger.info(f"[PCAP] Parsing {pcap_path} with scapy...")
        packets = rdpcap(pcap_path)
        result["total_packets"] = len(packets)

        # Track per-destination stats
        dest_stats: Dict[str, Dict[str, Any]] = {}  # ip:port:proto -> stats
        dns_map: Dict[str, list] = {}  # domain -> [ips]

        for pkt in packets:
            pkt_len = len(pkt)
            result["total_bytes"] += pkt_len

            # Extract IP layer
            ip_layer = None
            if IP in pkt:
                ip_layer = pkt[IP]
            elif IPv6 in pkt:
                ip_layer = pkt[IPv6]

            if not ip_layer:
                continue

            dst_ip = str(ip_layer.dst)
            src_ip = str(ip_layer.src)

            # Skip loopback and link-local
            if dst_ip.startswith("127.") or dst_ip.startswith("169.254."):
                continue

            # Determine protocol and port
            proto = "OTHER"
            dst_port = 0
            if TCP in pkt:
                proto = "TCP"
                dst_port = pkt[TCP].dport
                result["protocols"]["TCP"] = result["protocols"].get("TCP", 0) + 1
            elif UDP in pkt:
                proto = "UDP"
                dst_port = pkt[UDP].dport
                result["protocols"]["UDP"] = result["protocols"].get("UDP", 0) + 1
            else:
                proto_num = getattr(ip_layer, 'proto', getattr(ip_layer, 'nh', 0))
                if proto_num == 1:
                    proto = "ICMP"
                result["protocols"][proto] = result["protocols"].get(proto, 0) + 1

            # Extract DNS queries and responses
            if DNS in pkt:
                dns_pkt = pkt[DNS]
                # DNS Response
                if dns_pkt.ancount and dns_pkt.ancount > 0:
                    if DNSQR in pkt:
                        qname = pkt[DNSQR].qname
                        if isinstance(qname, bytes):
                            qname = qname.decode("utf-8", errors="replace")
                        qname = qname.rstrip(".")
                        for i in range(dns_pkt.ancount):
                            try:
                                rr = dns_pkt.an[i]
                                if hasattr(rr, 'rdata'):
                                    rdata = str(rr.rdata)
                                    if qname not in dns_map:
                                        dns_map[qname] = []
                                    if rdata not in dns_map[qname]:
                                        dns_map[qname].append(rdata)
                            except Exception:
                                pass
                # DNS Query
                elif DNSQR in pkt:
                    qname = pkt[DNSQR].qname
                    if isinstance(qname, bytes):
                        qname = qname.decode("utf-8", errors="replace")
                    qname = qname.rstrip(".")
                    if qname and qname not in dns_map:
                        dns_map[qname] = []

            # Track destination stats (outbound: from device perspective)
            key = f"{dst_ip}:{dst_port}:{proto}"
            if key not in dest_stats:
                dest_stats[key] = {
                    "ip": dst_ip,
                    "port": str(dst_port),
                    "protocol": proto,
                    "hostname": "",
                    "packets": 0,
                    "bytes_sent": 0,
                    "bytes_received": 0,
                    "first_seen": pkt.time if hasattr(pkt, 'time') else 0,
                    "last_seen": pkt.time if hasattr(pkt, 'time') else 0,
                }

            stats = dest_stats[key]
            stats["packets"] += 1
            stats["bytes_sent"] += pkt_len
            if hasattr(pkt, 'time'):
                if pkt.time < stats["first_seen"]:
                    stats["first_seen"] = pkt.time
                if pkt.time > stats["last_seen"]:
                    stats["last_seen"] = pkt.time

        # Resolve hostnames from DNS mappings
        ip_to_domain: Dict[str, str] = {}
        for domain, ips in dns_map.items():
            for ip in ips:
                ip_to_domain[ip] = domain

        # Build connection list and assign hostnames
        for key, stats in dest_stats.items():
            ip = stats["ip"]
            hostname = ip_to_domain.get(ip, "")

            # Skip very common system endpoints
            if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127."):
                continue

            # Convert timestamps
            first_ts = ""
            last_ts = ""
            try:
                if stats["first_seen"]:
                    first_ts = datetime.fromtimestamp(float(stats["first_seen"]), tz=timezone.utc).isoformat()
                if stats["last_seen"]:
                    last_ts = datetime.fromtimestamp(float(stats["last_seen"]), tz=timezone.utc).isoformat()
            except Exception:
                pass

            result["connections"].append({
                "ip": ip,
                "port": stats["port"],
                "protocol": stats["protocol"],
                "hostname": hostname,
                "destination": hostname or ip,
                "packets": stats["packets"],
                "bytes_sent": stats["bytes_sent"],
                "bytes_received": stats["bytes_received"],
                "first_seen": first_ts,
                "last_seen": last_ts,
                "direction": "OUTBOUND",
                "source": "pcap_capture",
            })

        result["dns_mappings"] = dns_map

        logger.info(
            f"[PCAP] Parsed {result['total_packets']} packets, "
            f"{len(result['connections'])} unique destinations, "
            f"{len(dns_map)} DNS domains, "
            f"{result['total_bytes']} bytes total"
        )

    except ImportError:
        logger.warning("[PCAP] scapy not installed — skipping PCAP analysis. Install with: pip install scapy")
    except Exception as e:
        logger.error(f"[PCAP] Failed to parse {pcap_path}: {e}")

    return result


# ── Session Management ──────────────────────────────────────────────

def start_monitoring_session(
    device_serial: str,
    case_dir: str,
    case_id: str,
    apk_path: str = "",
) -> Dict[str, Any]:
    """
    Start a real-time monitoring session on a physical device.
    Returns session info for the frontend to track.
    """
    session_id = str(uuid4())
    pentest_dir = os.path.join(case_dir, "pentest_analysis")
    os.makedirs(pentest_dir, exist_ok=True)

    # Get package name from APK if available
    target_package = ""
    if apk_path and os.path.exists(apk_path):
        target_package = vm_orchestrator.get_package_name(apk_path) or ""
    target_package = _clean_package_name(target_package)

    # Step 1: Snapshot packages before
    logger.info(f"[Pentest] Taking package snapshot BEFORE on {device_serial}")
    packages_before = _snapshot_packages(device_serial)
    if target_package:
        # Discard target_package so if it was already installed, it's still tracked for uninstall
        packages_before.discard(target_package)

    # Step 2: Install the target APK on the device
    apk_installed = False
    if apk_path and os.path.exists(apk_path):
        logger.info(f"[Pentest] Installing target APK on device: {apk_path}")
        install_result = vm_orchestrator._run_adb(
            ["install", "-r", "-g", apk_path],
            device=device_serial, timeout=120
        )
        # Check if package is installed on device
        current_check = _snapshot_packages(device_serial)
        if (install_result["success"] and "Success" in install_result.get("stdout", "")) or (target_package and target_package in current_check):
            apk_installed = True
            logger.info(f"[Pentest] APK verified installed on device: {target_package}")

            # Launch the APK on the device
            if target_package:
                logger.info(f"[Pentest] Launching {target_package} on device...")
                # Find the main launcher activity
                launch_result = vm_orchestrator._run_adb(
                    ["shell", "monkey", "-p", target_package,
                     "-c", "android.intent.category.LAUNCHER", "1"],
                    device=device_serial, timeout=15
                )
                if launch_result["success"]:
                    logger.info(f"[Pentest] APK launched on device via Monkey launcher")
                else:
                    # Fallback: try am start with main activity
                    vm_orchestrator._run_adb(
                        ["shell", "am", "start", "-n",
                         f"{target_package}/.MainActivity"],
                        device=device_serial, timeout=10
                    )
                # Give the app a moment to start
                time.sleep(2)
        else:
            logger.error(f"[Pentest] APK install failed: {install_result.get('error') or install_result.get('stdout', 'unknown')}")
    else:
        logger.warning(f"[Pentest] No APK path provided or file not found: {apk_path}")

    # Step 3: Install PCAPdroid for network capture
    pcapdroid_available = _install_pcapdroid(device_serial)

    # Step 4: Start PCAPdroid capture
    pcap_active = False
    if pcapdroid_available:
        pcap_active = _start_pcapdroid_capture(device_serial, pentest_dir)

    # Build session state
    session = {
        "session_id": session_id,
        "case_id": case_id,
        "case_dir": case_dir,
        "pentest_dir": pentest_dir,
        "device_serial": device_serial,
        "target_package": target_package,
        "apk_path": apk_path,
        "status": "monitoring",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "packages_before": packages_before,
        "child_apks_detected": [],
        "events": [],
        "network_activity": [],
        "pcap_active": pcap_active,
        "pcapdroid_installed": pcapdroid_available,
        "apk_installed": apk_installed,
        "_logcat_proc": None,
    }

    _active_sessions[session_id] = session

    # Check if device has root access
    has_root = _check_root_access(device_serial)
    session["has_root"] = has_root
    if has_root:
        logger.info("[Pentest] Root access detected — enabling deep scanning")
    else:
        logger.info("[Pentest] No root — using standard ADB monitoring")

    # Step 5: Setup Frida instrumentation (if root is available)
    frida_mgr = None
    frida_active = False
    if has_root and target_package:
        try:
            from app.engines.dynamic.frida_manager import FridaManager
            frida_mgr = FridaManager(device_serial, target_package)
            if frida_mgr.is_available():
                if frida_mgr.setup_frida_server():
                    time.sleep(1)  # Let frida-server stabilize
                    if frida_mgr.attach():
                        hook_results = frida_mgr.inject_hooks()
                        frida_active = any(hook_results.values())
                        if frida_active:
                            logger.info(f"[Pentest] Frida hooks active: {hook_results}")
                        else:
                            logger.warning("[Pentest] Frida attached but no hooks loaded")
                    else:
                        logger.warning("[Pentest] Frida attach failed — app may not be running")
                else:
                    logger.warning("[Pentest] Frida server setup failed")
            else:
                logger.info("[Pentest] Frida Python module not available")
        except Exception as e:
            logger.warning(f"[Pentest] Frida integration failed: {e}")
            frida_mgr = None

    session["_frida_mgr"] = frida_mgr
    session["frida_active"] = frida_active

    # Step 6: Start all background monitoring threads
    logcat_thread = threading.Thread(
        target=_logcat_monitor_thread, args=(session,), daemon=True
    )
    logcat_thread.start()

    net_thread = threading.Thread(
        target=_network_monitor_thread, args=(session,), daemon=True
    )
    net_thread.start()

    pkg_poll_thread = threading.Thread(
        target=_package_poll_thread, args=(session,), daemon=True
    )
    pkg_poll_thread.start()

    act_thread = threading.Thread(
        target=_activity_track_thread, args=(session,), daemon=True
    )
    act_thread.start()

    session["_logcat_thread"] = logcat_thread
    session["_net_thread"] = net_thread
    session["_pkg_poll_thread"] = pkg_poll_thread
    session["_act_thread"] = act_thread

    logger.info(f"[Pentest] Monitoring session {session_id} active on {device_serial}")

    return {
        "session_id": session_id,
        "device_serial": device_serial,
        "target_package": target_package,
        "pcapdroid_active": pcap_active,
        "frida_active": frida_active,
        "has_root": has_root,
        "apk_installed": apk_installed,
        "status": "monitoring",
        "started_at": session["started_at"],
    }


def get_session_status(session_id: str) -> Dict[str, Any]:
    """Get live stats from an active monitoring session."""
    session = _active_sessions.get(session_id)
    if not session:
        return {"error": "Session not found", "status": "not_found"}

    elapsed = 0
    if session.get("started_at"):
        start = datetime.fromisoformat(session["started_at"])
        elapsed = (datetime.now(timezone.utc) - start).total_seconds()

    return {
        "session_id": session_id,
        "status": session["status"],
        "elapsed_seconds": round(elapsed),
        "events_captured": len(session["events"]),
        "network_connections": len(session["network_activity"]),
        "child_apks_detected": len(session["child_apks_detected"]),
        "child_apk_details": session["child_apks_detected"],
        "pcapdroid_active": session.get("pcap_active", False),
        "device_serial": session["device_serial"],
    }


# ── Package Uninstallation Helper ────────────────────────────────────

def _uninstall_packages_from_device(device: str, packages: List[str]) -> List[str]:
    """
    Forcefully and completely uninstalls a list of packages from a device.
    Uses multi-stage uninstall:
    1. Force-stop all activities
    2. Clear app data (pm clear)
    3. Standard adb uninstall
    4. Shell pm uninstall
    5. pm uninstall --user 0
    6. pm uninstall -k --user 0 (keep data but remove)
    7. pm disable-user (last resort)
    8. Verify removal
    """
    uninstalled = []
    failed = []
    seen = set()

    for raw_pkg in packages:
        pkg = _clean_package_name(raw_pkg)
        if not pkg or pkg == PCAPDROID_PACKAGE or pkg in seen:
            continue
        seen.add(pkg)

        logger.info(f"[Pentest] Initiating force-stop and uninstallation of: {pkg} from {device}")

        # 1. Force stop all activities and background services for the package
        vm_orchestrator._run_adb(["shell", "am", "force-stop", pkg], device=device, timeout=8)
        time.sleep(0.5)

        # 2. Clear app data first (removes caches, databases, shared prefs)
        vm_orchestrator._run_adb(["shell", "pm", "clear", pkg], device=device, timeout=10)

        # 3. Try standard adb uninstall
        u_res = vm_orchestrator._run_adb(["uninstall", pkg], device=device, timeout=15)
        success = u_res["success"] and "Success" in (u_res.get("stdout") or "")

        # 4. Fallback to shell pm uninstall
        if not success:
            logger.info(f"[Pentest] 'adb uninstall' was not definitive. Trying 'pm uninstall {pkg}'...")
            pm_res = vm_orchestrator._run_adb(["shell", "pm", "uninstall", pkg], device=device, timeout=12)
            success = pm_res["success"] and "Success" in (pm_res.get("stdout") or "")

        # 5. Fallback to pm uninstall --user 0 (cleans from primary user / app drawer completely)
        if not success:
            logger.info(f"[Pentest] Trying 'pm uninstall --user 0 {pkg}'...")
            user_res = vm_orchestrator._run_adb(["shell", "pm", "uninstall", "--user", "0", pkg], device=device, timeout=12)
            success = user_res["success"] and "Success" in (user_res.get("stdout") or "")

        # 6. Try removing for ALL users
        if not success:
            logger.info(f"[Pentest] Trying 'pm uninstall -k --user 0 {pkg}'...")
            vm_orchestrator._run_adb(
                ["shell", "pm", "uninstall", "-k", "--user", "0", pkg],
                device=device, timeout=12
            )

        # 7. Last resort: disable the package so it can't run
        if not success:
            logger.info(f"[Pentest] Trying to disable package: {pkg}...")
            vm_orchestrator._run_adb(
                ["shell", "pm", "disable-user", "--user", "0", pkg],
                device=device, timeout=10
            )

        # 8. Verify if package is still installed
        check = vm_orchestrator._run_adb(["shell", "pm", "list", "packages", pkg], device=device, timeout=8)
        still_there = check["success"] and f"package:{pkg}" in check.get("stdout", "")

        if not still_there:
            uninstalled.append(pkg)
            logger.info(f"[Pentest] [SUCCESS] App {pkg} completely uninstalled from device {device}!")
        else:
            failed.append(pkg)
            logger.warning(f"[Pentest] [FAILED] Package {pkg} is still listed on device {device}")

    # Retry failed packages one more time with root if available
    if failed:
        has_root = _check_root_access(device)
        if has_root:
            for pkg in failed:
                logger.info(f"[Pentest] Retrying with root: {pkg}")
                vm_orchestrator._run_adb(
                    ["shell", "su", "-c", f"pm uninstall {pkg}"],
                    device=device, timeout=12
                )
                vm_orchestrator._run_adb(
                    ["shell", "su", "-c", f"pm uninstall --user 0 {pkg}"],
                    device=device, timeout=12
                )
                check2 = vm_orchestrator._run_adb(["shell", "pm", "list", "packages", pkg], device=device, timeout=8)
                if not (check2["success"] and f"package:{pkg}" in check2.get("stdout", "")):
                    uninstalled.append(pkg)
                    logger.info(f"[Pentest] [SUCCESS] Root uninstall succeeded for {pkg}")

    return uninstalled


def uninstall_single_package(device_serial: str, package_name: str) -> Dict[str, Any]:
    """
    Uninstalls a specific package from a connected device.
    """
    cleaned = _clean_package_name(package_name)
    if not cleaned:
        return {"success": False, "error": "Invalid package name"}
    uninstalled = _uninstall_packages_from_device(device_serial, [cleaned])
    return {
        "device": device_serial,
        "package_name": cleaned,
        "success": cleaned in uninstalled,
        "uninstalled": uninstalled,
    }


def cleanup_device_for_case(case_dir: str, device_serial: str, target_package: str = "") -> Dict[str, Any]:
    """
    Manual cleanup utility to remove target APK and all child APKs from the phone.
    Can be called on demand via API or button in UI.
    """
    packages = []
    if target_package:
        packages.append(_clean_package_name(target_package))

    # Check report for any recorded child APKs
    pentest_report = os.path.join(case_dir, "pentest_analysis", "pentest_report.json")
    if os.path.exists(pentest_report):
        try:
            with open(pentest_report, "r") as f:
                data = json.load(f)
                pdata = data.get("pentest_data", {})
                for c in pdata.get("child_apks", []):
                    if c.get("package_name"):
                        packages.append(c["package_name"])
        except Exception:
            pass

    # Also check dynamic report
    dyn_report = os.path.join(case_dir, "dynamic_analysis", "dynamic_report.json")
    if os.path.exists(dyn_report):
        try:
            with open(dyn_report, "r") as f:
                data = json.load(f)
                for evt in data.get("events", []):
                    cls_name = evt.get("class_name", "")
                    if cls_name and "." in cls_name and len(cls_name) < 100:
                        packages.append(cls_name)
        except Exception:
            pass

    uninstalled = _uninstall_packages_from_device(device_serial, packages)
    return {
        "device": device_serial,
        "targeted_packages": packages,
        "uninstalled_packages": uninstalled,
        "success": True,
    }


def stop_monitoring_session(session_id: str) -> Dict[str, Any]:
    """
    Stop a monitoring session and produce the final analysis report.
    Diffs packages, analyzes child APKs, uninstalls everything immediately, pulls PCAP, enriches with VT.
    """
    session = _active_sessions.get(session_id)
    if not session:
        return {"error": "Session not found", "status": "failed"}

    session["status"] = "finalizing"
    device = session["device_serial"]
    pentest_dir = session["pentest_dir"]
    case_dir = session["case_dir"]
    target_clean = _clean_package_name(session.get("target_package", ""))

    logger.info(f"[Pentest] Stopping session {session_id} on {device}")

    # Step 1: Kill logcat process
    logcat_proc = session.get("_logcat_proc")
    if logcat_proc and logcat_proc.poll() is None:
        logcat_proc.terminate()
        try:
            logcat_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            logcat_proc.kill()

    # Step 2: Stop PCAPdroid and pull PCAP
    pcap_path = None
    pcap_analysis = None
    if session.get("pcap_active"):
        pcap_path = _stop_pcapdroid_capture(device, pentest_dir)
        # Parse the PCAP file for comprehensive network analysis
        if pcap_path:
            pcap_analysis = _parse_pcap_file(pcap_path)

    # Step 2.5: Collect Frida data (if active)
    frida_mgr = session.get("_frida_mgr")
    frida_data = {
        "active": session.get("frida_active", False),
        "network_events": [],
        "upi_events": [],
        "dns_events": [],
        "intent_events": [],
        "ssl_bypasses": 0,
        "total_messages": 0,
    }

    if frida_mgr and session.get("frida_active"):
        try:
            # Collect all Frida messages before detaching
            all_msgs = frida_mgr.collect_messages()
            frida_data["total_messages"] = len(all_msgs)
            frida_data["ssl_bypasses"] = sum(1 for m in all_msgs if m.get("type") == "ssl_bypass")

            # Merge Frida network activity into session network_activity
            frida_network = frida_mgr.to_network_activity()
            for fn in frida_network:
                fn["attributed_package"] = session.get("target_package", "parent")
                session["network_activity"].append(fn)
            frida_data["network_events"] = frida_network

            # Merge Frida behavior events into session events
            frida_events = frida_mgr.to_behavior_events()
            session["events"].extend(frida_events)

            # Collect categorized events for the report
            frida_data["upi_events"] = frida_mgr.collect_upi_events()
            frida_data["dns_events"] = frida_mgr.collect_dns_events()
            frida_data["intent_events"] = frida_mgr.collect_intent_events()

            logger.info(
                f"[Pentest] Frida data collected: {frida_data['total_messages']} messages, "
                f"{len(frida_network)} network events, {len(frida_data['upi_events'])} UPI events, "
                f"{frida_data['ssl_bypasses']} SSL bypasses"
            )

            # Detach Frida cleanly before uninstalling apps
            frida_mgr.detach()

        except Exception as e:
            logger.error(f"[Pentest] Frida data collection failed: {e}")
            try:
                frida_mgr.detach()
            except Exception:
                pass

    # Step 3: Package diff — detect child APKs
    logger.info("[Pentest] Taking package snapshot AFTER")
    packages_after = _snapshot_packages(device)
    new_packages = {p for p in (packages_after - session["packages_before"]) if _clean_package_name(p)}

    # Remove PCAPdroid and target package from the diff
    new_packages.discard(PCAPDROID_PACKAGE)
    if target_clean:
        new_packages.discard(target_clean)

    logger.info(f"[Pentest] {len(new_packages)} new packages detected: {new_packages}")

    # Step 4: Analyze each child APK
    child_apk_reports = []
    child_network = []
    for raw_pkg in new_packages:
        pkg = _clean_package_name(raw_pkg)
        if not pkg:
            continue
        logger.info(f"[Pentest] Analyzing child APK: {pkg}")
        pkg_info = _analyze_new_package(device, pkg)
        child_apk_reports.append(pkg_info)

        # Get network connections for the child
        pkg_net = _get_package_network_connections(device, pkg)
        child_network.extend(pkg_net)

        # Add as event if not already detected via logcat
        already_detected = any(
            c.get("package_name") == pkg for c in session["child_apks_detected"]
        )
        if not already_detected:
            session["events"].append({
                "id": str(uuid4()),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "api_call": f"CHILD_APK_DETECTED: {pkg}",
                "description": f"Package diff detected new {'HIDDEN' if pkg_info['is_hidden'] else ''} child APK: {pkg}" +
                               (f" — RUNNING in background!" if pkg_info["is_running"] else ""),
                "category": "dropper",
                "risk_level": "CRITICAL" if pkg_info["is_hidden"] else "HIGH",
                "class_name": "android.content.pm.PackageInstaller",
                "source": "manual_pentest",
            })

    # Step 4b: Merge runtime-detected child APKs into child_apk_reports
    # The polling thread may have detected child APKs during the session that
    # are no longer present in the post-session diff (e.g., self-deleting malware,
    # or APKs that were already uninstalled by the time the final diff runs).
    already_in_reports = {r["package_name"] for r in child_apk_reports}
    for runtime_child in session.get("child_apks_detected", []):
        child_pkg_name = runtime_child.get("package_name", "")
        if child_pkg_name and child_pkg_name not in already_in_reports:
            logger.info(f"[Pentest] Merging runtime-detected child APK into report: {child_pkg_name}")
            child_apk_reports.append(runtime_child)
            already_in_reports.add(child_pkg_name)

    # Add child network to session
    session["network_activity"].extend(child_network)

    # Step 5: Pull child APKs from device for static analysis (before uninstalling)
    pulled_child_apks = []
    for report in child_apk_reports:
        if report["install_path"]:
            local_path = os.path.join(pentest_dir, f"child_{report['package_name']}.apk")
            pull_result = vm_orchestrator._run_adb(
                ["pull", report["install_path"], local_path],
                device=device, timeout=30
            )
            if pull_result["success"] and os.path.exists(local_path):
                pulled_child_apks.append({
                    "package_name": report["package_name"],
                    "local_path": local_path,
                })
                logger.info(f"[Pentest] Pulled child APK: {report['package_name']}")

    # Step 6: IMMEDIATELY UNINSTALL TARGET APK AND ALL CHILD APKS FROM DEVICE
    # We do this NOW so the phone is cleaned immediately while analysis continues
    packages_to_uninstall = []
    if target_clean:
        packages_to_uninstall.append(target_clean)
    for pkg in new_packages:
        clean_p = _clean_package_name(pkg)
        if clean_p and clean_p not in packages_to_uninstall:
            packages_to_uninstall.append(clean_p)
    for child in session.get("child_apks_detected", []):
        pkg_name = _clean_package_name(child.get("package_name", ""))
        if pkg_name and pkg_name not in packages_to_uninstall:
            packages_to_uninstall.append(pkg_name)

    uninstalled = _uninstall_packages_from_device(device, packages_to_uninstall)

    # Step 7: Run static analysis on child APKs
    child_static_results = []
    for child in pulled_child_apks:
        try:
            from app.engines.static import run_full_static_analysis
            child_case_dir = os.path.join(pentest_dir, f"child_{child['package_name']}")
            os.makedirs(child_case_dir, exist_ok=True)
            child_apk_dest = os.path.join(child_case_dir, f"{child['package_name']}.apk")
            shutil.copy2(child["local_path"], child_apk_dest)

            logger.info(f"[Pentest] Running static analysis on child: {child['package_name']}")
            child_result = run_full_static_analysis(child_apk_dest, child_case_dir)
            child_static_results.append({
                "package_name": child["package_name"],
                "result": child_result,
            })
        except Exception as e:
            logger.error(f"[Pentest] Static analysis of child {child['package_name']} failed: {e}")

    # Step 8: VirusTotal enrichment
    try:
        from app.engines import virustotal_client
        if virustotal_client._has_key():
            if session["apk_path"] and os.path.exists(session["apk_path"]):
                file_hash = virustotal_client.sha256_of_file(session["apk_path"])
                behaviours = virustotal_client.get_behaviours(file_hash)
                if behaviours:
                    deep_events = virustotal_client.extract_sandbox_events(behaviours)
                    existing_apis = {e["api_call"] for e in session["events"]}
                    for de in deep_events:
                        if de["api_call"] not in existing_apis:
                            session["events"].append(de)
                            existing_apis.add(de["api_call"])

                    deep_network = virustotal_client.extract_network_from_behaviours(behaviours)
                    existing_dests = {n["destination"] for n in session["network_activity"]}
                    for dn in deep_network:
                        if dn["destination"] not in existing_dests:
                            session["network_activity"].append(dn)
                            existing_dests.add(dn["destination"])
    except Exception as e:
        logger.debug(f"[Pentest] VT enrichment skipped: {e}")

    # Step 9: Merge PCAP analysis data into network_activity
    if pcap_analysis and pcap_analysis.get("connections"):
        existing_ips = {f"{n.get('ip', '')}:{n.get('port', '')}" for n in session["network_activity"]}
        dns_mappings = pcap_analysis.get("dns_mappings", {})

        # Build IP-to-domain lookup from PCAP DNS data
        pcap_ip_to_domain = {}
        for domain, ips in dns_mappings.items():
            for ip in ips:
                pcap_ip_to_domain[ip] = domain

        # Enrich existing network_activity entries with PCAP DNS data
        for existing_conn in session["network_activity"]:
            conn_ip = existing_conn.get("ip", "")
            if conn_ip in pcap_ip_to_domain and not existing_conn.get("hostname"):
                domain = pcap_ip_to_domain[conn_ip]
                existing_conn["hostname"] = domain
                existing_conn["destination"] = domain

        # Add new connections from PCAP that weren't caught by runtime polling
        for pcap_conn in pcap_analysis["connections"]:
            key = f"{pcap_conn['ip']}:{pcap_conn['port']}"
            if key not in existing_ips:
                existing_ips.add(key)
                session["network_activity"].append(pcap_conn)

        logger.info(
            f"[Pentest] PCAP enrichment: {pcap_analysis['total_packets']} packets, "
            f"{len(pcap_analysis['connections'])} unique destinations, "
            f"{len(dns_mappings)} DNS domains resolved"
        )

    # Step 10: Compute risk score
    from app.engines.dynamic.heuristic_analyzer import compute_heuristic_risk
    risk_data = compute_heuristic_risk(session["events"])

    child_risk_boost = sum(
        30 if r["risk_level"] == "CRITICAL" else 15 if r["risk_level"] == "HIGH" else 5
        for r in child_apk_reports
    )
    final_risk = min(risk_data["risk_score"] + child_risk_boost, 100)

    end_time = datetime.now(timezone.utc)

    # Compute total app traffic
    app_traffic = session.get("_app_traffic", {})

    # Step 10.5: Network Attribution — Tag each connection with parent/child APK
    child_pkg_names = {r.get("package_name", "") for r in child_apk_reports}
    for conn in session["network_activity"]:
        if not conn.get("attributed_package"):
            # Default to parent package
            conn["attributed_package"] = target_clean or "parent"
        # Check if the connection source is from a child APK
        if conn.get("source") == "child_apk_network":
            # Already has attribution from child APK polling
            pass
        elif conn.get("attributed_package") in child_pkg_names:
            conn["is_child_apk_connection"] = True

    # Step 10.6: Static-Dynamic Cross-Reference
    # Load static analysis IOCs and match them to dynamic network connections
    static_iocs = {}
    try:
        static_report_path = os.path.join(case_dir, "static_analysis", "static_report.json")
        if os.path.exists(static_report_path):
            with open(static_report_path, "r") as f:
                static_report = json.load(f)

            # Extract IPs, domains, URLs from static analysis
            iocs = static_report.get("iocs", {})
            for ioc_ip in iocs.get("ips", []):
                ip_addr = ioc_ip if isinstance(ioc_ip, str) else ioc_ip.get("value", "")
                location = ioc_ip.get("location", "") if isinstance(ioc_ip, dict) else ""
                if ip_addr:
                    static_iocs[ip_addr] = {"type": "ip", "location": location}

            for ioc_domain in iocs.get("domains", []):
                domain = ioc_domain if isinstance(ioc_domain, str) else ioc_domain.get("value", "")
                location = ioc_domain.get("location", "") if isinstance(ioc_domain, dict) else ""
                if domain:
                    static_iocs[domain] = {"type": "domain", "location": location}

            for ioc_url in iocs.get("urls", []):
                url = ioc_url if isinstance(ioc_url, str) else ioc_url.get("value", "")
                location = ioc_url.get("location", "") if isinstance(ioc_url, dict) else ""
                if url:
                    # Extract domain from URL
                    import urllib.parse
                    parsed = urllib.parse.urlparse(url)
                    if parsed.hostname:
                        static_iocs[parsed.hostname] = {"type": "url", "url": url, "location": location}

            logger.info(f"[Pentest] Loaded {len(static_iocs)} IOCs from static analysis for cross-reference")
    except Exception as e:
        logger.debug(f"[Pentest] Static IOC loading skipped: {e}")

    # Cross-reference: tag network connections that match static IOCs
    for conn in session["network_activity"]:
        conn_ip = conn.get("ip", "")
        conn_host = conn.get("hostname", "")
        conn_dest = conn.get("destination", "")

        # Check if IP, hostname, or destination matches any static IOC
        for indicator, ioc_info in static_iocs.items():
            if indicator in (conn_ip, conn_host, conn_dest):
                conn["static_reference"] = {
                    "matched_ioc": indicator,
                    "ioc_type": ioc_info.get("type", ""),
                    "code_location": ioc_info.get("location", ""),
                    "url": ioc_info.get("url", ""),
                }
                break

    # Build final result
    result = {
        "phase": "dynamic",
        "status": "completed",
        "mode": "manual_pentest",
        "apk_path": session["apk_path"],
        "started_at": session["started_at"],
        "completed_at": end_time.isoformat(),
        "duration_seconds": (end_time - datetime.fromisoformat(session["started_at"])).total_seconds(),
        "device": device,
        "total_events": len(session["events"]),
        "events": session["events"],
        "network_activity": session["network_activity"],
        "risk_score": final_risk,
        "risk_level": "critical" if final_risk >= 75 else "high" if final_risk >= 50 else "medium" if final_risk >= 25 else "low",
        "risk_breakdown": risk_data["risk_breakdown"],
        "behaviors": risk_data["behaviors"],
        "errors": [],
        "pentest_data": {
            "child_apks": child_apk_reports,
            "child_apk_count": len(child_apk_reports),
            "hidden_child_apks": [r for r in child_apk_reports if r["is_hidden"]],
            "running_child_apks": [r for r in child_apk_reports if r["is_running"]],
            "child_static_analysis": child_static_results,
            "pcap_file": pcap_path,
            "pcap_analysis": {
                "total_packets": pcap_analysis["total_packets"] if pcap_analysis else 0,
                "total_bytes": pcap_analysis["total_bytes"] if pcap_analysis else 0,
                "protocols": pcap_analysis["protocols"] if pcap_analysis else {},
                "dns_domains": list(pcap_analysis["dns_mappings"].keys()) if pcap_analysis else [],
            } if pcap_analysis else None,
            "pcapdroid_used": session.get("pcap_active", False),
            "frida_used": session.get("frida_active", False),
            "frida_data": frida_data,
            "app_traffic": app_traffic,
            "packages_before_count": len(session["packages_before"]),
            "packages_after_count": len(packages_after),
            "uninstalled_packages": uninstalled,
            "static_crossref_matches": sum(
                1 for c in session["network_activity"] if c.get("static_reference")
            ),
        },
    }

    # Save report
    report_path = os.path.join(pentest_dir, "pentest_report.json")
    try:
        with open(report_path, "w") as f:
            json.dump(result, f, indent=2, default=str)
    except Exception as e:
        logger.error(f"[Pentest] Failed to save report: {e}")

    # Clean up session
    session["status"] = "completed"
    session["result"] = result

    logger.info(
        f"[Pentest] Session {session_id} complete — "
        f"Risk: {final_risk}, Events: {len(session['events'])}, "
        f"Child APKs: {len(child_apk_reports)}, "
        f"Uninstalled: {len(uninstalled)}"
    )

    return result


def get_active_session_for_case(case_id: str) -> Optional[str]:
    """Check if there's an active monitoring session for a case."""
    for sid, session in _active_sessions.items():
        if session.get("case_id") == case_id and session.get("status") == "monitoring":
            return sid
    return None
