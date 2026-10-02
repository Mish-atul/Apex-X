"""
Heuristic Behavioral Analyzer — Static-Informed Dynamic Analysis (Layer 2)
Scans JADX-decompiled Java source for dangerous API call patterns.
Produces structured behavioral events identical to real emulator output.
Used as fallback when no emulator is available.
"""

from app.utils.file_utils import long_path
import os
import re
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

# ── Dangerous API Patterns ────────────────────────────────────────
# Each pattern: (regex, category, api_name, risk_level, description)
API_PATTERNS = [
    # Dynamic Code Loading
    (r"DexClassLoader\s*\(", "dynamic_loading", "DexClassLoader()", "CRITICAL",
     "Dynamic DEX class loading — can load malicious code at runtime"),
    (r"PathClassLoader\s*\(", "dynamic_loading", "PathClassLoader()", "HIGH",
     "Custom class loader — potential dynamic code loading"),
    (r"Class\.forName\s*\(", "dynamic_loading", "Class.forName()", "MEDIUM",
     "Reflection-based class loading — very common, could be obfuscation"),
    (r"loadLibrary\s*\(", "dynamic_loading", "System.loadLibrary()", "HIGH",
     "Native library loading — potential native payload"),
    (r"Runtime\.getRuntime\(\)\.exec", "command_exec", "Runtime.exec()", "CRITICAL",
     "OS command execution — can run arbitrary commands"),
    (r"ProcessBuilder\s*\(", "command_exec", "ProcessBuilder()", "CRITICAL",
     "Process creation — can execute arbitrary programs"),

    # Network Activity
    (r"HttpURLConnection|openConnection\s*\(", "network", "HttpURLConnection.openConnection()", "LOW",
     "HTTP connection — standard network communication"),
    (r"OkHttpClient|OkHttp", "network", "OkHttpClient()", "MEDIUM",
     "OkHttp HTTP client — network communication"),
    (r"Retrofit\.Builder", "network", "Retrofit.Builder()", "MEDIUM",
     "Retrofit HTTP client — API communication"),
    (r"WebView.*loadUrl\s*\(", "network", "WebView.loadUrl()", "HIGH",
     "WebView URL loading — potential phishing or data exfil"),
    (r"addJavascriptInterface\s*\(", "network", "WebView.addJavascriptInterface()", "CRITICAL",
     "JavaScript bridge — allows JS to call Java methods"),
    (r"new\s+Socket\s*\(", "network", "Socket()", "HIGH",
     "Raw socket connection — potential C2 communication"),
    (r"ServerSocket\s*\(", "network", "ServerSocket()", "CRITICAL",
     "Server socket — opens listening port on device"),
    (r"DatagramSocket\s*\(", "network", "DatagramSocket()", "HIGH",
     "UDP socket — potential covert communication"),

    # SMS Operations
    (r"sendTextMessage\s*\(", "sms", "SmsManager.sendTextMessage()", "CRITICAL",
     "Sends SMS messages — premium SMS fraud or data exfil"),
    (r"sendMultipartTextMessage\s*\(", "sms", "SmsManager.sendMultipartTextMessage()", "CRITICAL",
     "Sends multipart SMS — potential fraud"),
    (r"content://sms", "sms", "ContentResolver.query(sms)", "CRITICAL",
     "Reads SMS inbox — credential theft or OTP interception"),

    # Data Exfiltration
    (r"getDeviceId\s*\(", "data_exfil", "TelephonyManager.getDeviceId()", "HIGH",
     "Reads device IMEI — tracking/fingerprinting"),
    (r"getSubscriberId\s*\(", "data_exfil", "TelephonyManager.getSubscriberId()", "HIGH",
     "Reads subscriber ID (IMSI) — tracking"),
    (r"getSimSerialNumber\s*\(", "data_exfil", "TelephonyManager.getSimSerialNumber()", "HIGH",
     "Reads SIM serial — tracking/fingerprinting"),
    (r"getLine1Number\s*\(", "data_exfil", "TelephonyManager.getLine1Number()", "HIGH",
     "Reads phone number — PII theft"),
    (r"content://contacts|ContactsContract", "data_exfil", "ContentResolver.query(contacts)", "HIGH",
     "Reads contacts — data exfiltration"),
    (r"content://call_log", "data_exfil", "ContentResolver.query(call_log)", "HIGH",
     "Reads call log — surveillance"),
    (r"getAccounts\s*\(", "data_exfil", "AccountManager.getAccounts()", "HIGH",
     "Reads device accounts — PII theft"),
    (r"ClipboardManager.*getText|getPrimaryClip", "data_exfil", "ClipboardManager.getText()", "MEDIUM",
     "Reads clipboard — potential credential theft"),

    # Crypto Operations
    (r"Cipher\.getInstance\s*\(", "crypto", "Cipher.getInstance()", "MEDIUM",
     "Cryptographic cipher — may encrypt/decrypt data"),
    (r"SecretKeySpec\s*\(", "crypto", "SecretKeySpec()", "MEDIUM",
     "Secret key generation — potential data encryption"),
    (r"MessageDigest\.getInstance\s*\(", "crypto", "MessageDigest.getInstance()", "LOW",
     "Hash computation — fingerprinting or integrity check"),
    (r"KeyStore\.getInstance\s*\(", "crypto", "KeyStore.getInstance()", "MEDIUM",
     "Keystore access — certificate/key manipulation"),

    # Camera & Microphone
    (r"Camera\.open\s*\(|CameraManager.*openCamera", "surveillance", "Camera.open()", "CRITICAL",
     "Camera access — covert photo/video capture"),
    (r"AudioRecord\s*\(|MediaRecorder.*setAudioSource", "surveillance", "AudioRecord()", "CRITICAL",
     "Microphone access — covert audio recording"),
    (r"getLastKnownLocation\s*\(|requestLocationUpdates", "surveillance", "LocationManager.getLastKnownLocation()", "HIGH",
     "Location tracking — surveillance"),

    # Evasion Techniques
    (r"isDebuggerConnected\s*\(", "evasion", "Debug.isDebuggerConnected()", "HIGH",
     "Debugger detection — anti-analysis evasion"),
    (r"android\.os\.Debug", "evasion", "android.os.Debug", "MEDIUM",
     "Debug class usage — potential anti-debugging"),
    (r"ro\.debuggable|ro\.secure", "evasion", "System property check", "HIGH",
     "System property check — emulator/root detection"),
    (r"su\b|/system/xbin/su|/system/bin/su|Superuser", "evasion", "Root detection/usage", "CRITICAL",
     "Root check or root exploitation attempt"),
    (r"test-keys|generic.*:userdebug|sdk_gphone", "evasion", "Emulator detection", "HIGH",
     "Emulator fingerprint check — anti-analysis"),
    (r"getInstallerPackageName\s*\(", "evasion", "PackageManager.getInstallerPackageName()", "MEDIUM",
     "Installation source check — anti-sideloading"),

    # Device Admin
    (r"DevicePolicyManager|DeviceAdminReceiver", "persistence", "DevicePolicyManager", "CRITICAL",
     "Device admin API — potential ransomware or MDM abuse"),
    (r"setComponentEnabledSetting\s*\(", "persistence", "PackageManager.setComponentEnabledSetting()", "HIGH",
     "Component toggling — hide app icon or enable hidden receivers"),
    (r"AlarmManager.*setRepeating|setExact", "persistence", "AlarmManager.setRepeating()", "MEDIUM",
     "Scheduled alarm — persistence mechanism"),
    (r"RECEIVE_BOOT_COMPLETED", "persistence", "BOOT_COMPLETED receiver", "HIGH",
     "Boot persistence — auto-starts after reboot"),

    # File Operations
    (r"getExternalStorageDirectory\s*\(", "file_io", "Environment.getExternalStorageDirectory()", "MEDIUM",
     "External storage access"),
    (r"openFileOutput\s*\(", "file_io", "Context.openFileOutput()", "LOW",
     "Internal file write"),
    (r"SharedPreferences.*edit\(\).*put", "file_io", "SharedPreferences.edit()", "LOW",
     "Shared preferences write — stores app data"),
]


def scan_java_files(jadx_dir: str) -> List[Dict[str, Any]]:
    """
    Scan all .java files in the JADX output for dangerous API patterns.
    Returns a list of BehaviorEvent dicts.
    """
    events: List[Dict[str, Any]] = []
    seen_apis: set = set()  # Deduplicate by (api, file)

    sources_dir = os.path.join(jadx_dir, "sources")
    if not os.path.isdir(sources_dir):
        sources_dir = jadx_dir

    java_files = []
    for root, dirs, files in os.walk(long_path(sources_dir)):
        # Skip common library/framework packages
        rel = os.path.relpath(root, long_path(sources_dir)).replace("\\", "/")
        if any(skip in rel for skip in [
            "android/support", "androidx/", "com/google/android",
            "kotlin/", "kotlinx/", "org/intellij", "org/jetbrains",
            "com/squareup", "okhttp3/", "retrofit2/", "io/reactivex",
            "com/bumptech/glide", "com/facebook/", "dagger/",
        ]):
            continue
        for f in files:
            if f.endswith(".java"):
                java_files.append(os.path.join(root, f))

    logger.info(f"Heuristic scanner: scanning {len(java_files)} Java files")

    base_time = datetime.now(timezone.utc) - timedelta(seconds=len(java_files))
    event_idx = 0

    for file_path in java_files:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            continue

        rel_path = os.path.relpath(file_path, long_path(sources_dir)).replace("\\", "/")

        # Extract class name from file
        class_name = os.path.splitext(os.path.basename(file_path))[0]

        for pattern, category, api_name, risk, description in API_PATTERNS:
            matches = list(re.finditer(pattern, content))
            if not matches:
                continue

            dedup_key = (api_name, rel_path)
            if dedup_key in seen_apis:
                continue
            seen_apis.add(dedup_key)

            # Find the line number of first match
            match_pos = matches[0].start()
            line_num = content[:match_pos].count("\n") + 1

            # Extract surrounding code context (±2 lines)
            lines = content.split("\n")
            ctx_start = max(0, line_num - 3)
            ctx_end = min(len(lines), line_num + 2)
            code_context = "\n".join(lines[ctx_start:ctx_end]).strip()
            if len(code_context) > 200:
                code_context = code_context[:200] + "..."

            event_idx += 1
            events.append({
                "id": f"heur-{event_idx}",
                "timestamp": (base_time + timedelta(seconds=event_idx)).isoformat(),
                "category": category,
                "api_call": api_name,
                "class_name": class_name,
                "file_path": rel_path,
                "line_number": line_num,
                "risk_level": risk,
                "description": description,
                "occurrences": len(matches),
                "code_context": code_context,
                "source": "heuristic_code_scan",
            })

    # Sort by risk level
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    events.sort(key=lambda e: risk_order.get(e["risk_level"], 4))

    logger.info(f"Heuristic scan complete: {len(events)} API patterns found")
    return events


def compute_heuristic_risk(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute a risk score and breakdown from heuristic events."""
    risk_weights = {"CRITICAL": 15, "HIGH": 8, "MEDIUM": 3, "LOW": 1}

    total = 0
    breakdown: Dict[str, int] = {}

    for evt in events:
        weight = risk_weights.get(evt["risk_level"], 0)
        total += weight
        cat = evt["category"]
        breakdown[cat] = breakdown.get(cat, 0) + weight

    # Cap at 100
    score = min(total, 100)

    behaviors = {
        "data_exfiltration": any(e["category"] == "data_exfil" for e in events),
        "c2_communication": any(e["category"] == "network" and e["risk_level"] in ("HIGH", "CRITICAL") for e in events),
        "surveillance": any(e["category"] == "surveillance" for e in events),
        "credential_theft": any(e["category"] == "sms" or e["api_call"] in ("ClipboardManager.getText()", "ContentResolver.query(contacts)") for e in events),
        "command_execution": any(e["category"] == "command_exec" for e in events),
        "evasion": any(e["category"] == "evasion" for e in events),
        "dynamic_loading": any(e["category"] == "dynamic_loading" for e in events),
        "persistence": any(e["category"] == "persistence" for e in events),
    }

    risk_level = "low"
    if score >= 75:
        risk_level = "critical"
    elif score >= 50:
        risk_level = "high"
    elif score >= 25:
        risk_level = "medium"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "risk_breakdown": breakdown,
        "behaviors": behaviors,
    }


def run_heuristic_analysis(case_dir: str) -> Dict[str, Any]:
    """
    Run heuristic behavioral analysis on JADX output.
    Returns a result dict compatible with the dynamic analysis schema.
    """
    start_time = datetime.now(timezone.utc)

    # Find JADX output directory
    jadx_dir = os.path.join(case_dir, "static_analysis", "jadx_output")
    if not os.path.isdir(jadx_dir):
        jadx_dir = os.path.join(case_dir, "jadx_output")
    if not os.path.isdir(jadx_dir):
        jadx_dir = os.path.join(case_dir, "jadx")
    if not os.path.isdir(jadx_dir):
        # Try to find any directory with Java files
        for name in os.listdir(case_dir):
            candidate = os.path.join(case_dir, name)
            if os.path.isdir(candidate):
                for root, dirs, files in os.walk(long_path(candidate)):
                    if any(f.endswith(".java") for f in files):
                        jadx_dir = candidate
                        break

    if not os.path.isdir(jadx_dir):
        return {
            "phase": "dynamic",
            "status": "skipped",
            "mode": "heuristic",
            "reason": "No JADX output found for heuristic scan",
            "events": [],
            "risk_score": 0,
        }

    events = scan_java_files(jadx_dir)
    risk_data = compute_heuristic_risk(events)

    end_time = datetime.now(timezone.utc)

    # Build network predictions from static IOCs
    network_predictions = []
    ioc_file = os.path.join(case_dir, "static_analysis", "ioc_report.json")
    if os.path.isfile(ioc_file):
        try:
            import json
            with open(ioc_file, "r") as f:
                ioc_data = json.load(f)
            for url in ioc_data.get("urls", []):
                network_predictions.append({
                    "destination": url, "protocol": "HTTPS",
                    "port": "443", "direction": "OUTBOUND",
                    "source": "Static IOC cross-reference",
                })
            for domain in ioc_data.get("domains", []):
                network_predictions.append({
                    "destination": domain, "protocol": "DNS",
                    "port": "53", "direction": "OUTBOUND",
                    "source": "Static IOC cross-reference",
                })
        except Exception:
            pass

    return {
        "phase": "dynamic",
        "status": "completed",
        "mode": "heuristic",
        "started_at": start_time.isoformat(),
        "completed_at": end_time.isoformat(),
        "duration_seconds": (end_time - start_time).total_seconds(),
        "total_events": len(events),
        "events": events,
        "network_activity": network_predictions,
        "risk_score": risk_data["risk_score"],
        "risk_level": risk_data["risk_level"],
        "risk_breakdown": risk_data["risk_breakdown"],
        "behaviors": risk_data["behaviors"],
        "errors": [],
    }
