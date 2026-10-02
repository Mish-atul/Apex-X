"""
Dynamic Analysis Engine

Layer 1 (default): real execution inside an Android emulator that is booted
automatically — no physical phone or USB cable required. All evidence is
scoped to the analysed app's Linux UID so system/background noise is excluded:
  * logcat filtered by UID (+ system_server lines naming the package)
  * sockets owned by the UID, polled throughout the run
  * full packet capture from the emulator NIC (DNS names, TLS SNI, byte counts)
  * AppOps runtime usage, running services, kernel per-UID traffic counters
  * packages silently installed during the run (dropper detection)

Layer 2 (only if no emulator can be started): code-level heuristic scan,
clearly labelled mode="heuristic".
"""

import os
import re
import time
import json
import logging
import threading
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from app.engines.dynamic import vm_orchestrator
from app.engines.dynamic import heuristic_analyzer
from app.engines.dynamic import emulator_manager
from app.engines.dynamic import ui_explorer

logger = logging.getLogger(__name__)

DEFAULT_ANALYSIS_DURATION = 90
NETWORK_POLL_INTERVAL = 2

# AppOps that indicate sensitive behaviour when actually exercised at runtime
_APPOP_RISK = {
    "READ_SMS": "CRITICAL", "RECEIVE_SMS": "CRITICAL", "SEND_SMS": "CRITICAL", "WRITE_SMS": "CRITICAL",
    "READ_CONTACTS": "HIGH", "READ_CALL_LOG": "HIGH", "CALL_PHONE": "HIGH", "READ_PHONE_STATE": "HIGH",
    "READ_PHONE_NUMBERS": "HIGH", "FINE_LOCATION": "HIGH", "COARSE_LOCATION": "MEDIUM",
    "CAMERA": "HIGH", "RECORD_AUDIO": "HIGH", "SYSTEM_ALERT_WINDOW": "HIGH",
    "PROJECT_MEDIA": "CRITICAL", "BIND_ACCESSIBILITY_SERVICE": "CRITICAL", "GET_ACCOUNTS": "MEDIUM",
    "READ_EXTERNAL_STORAGE": "MEDIUM", "WRITE_EXTERNAL_STORAGE": "MEDIUM", "READ_MEDIA_IMAGES": "MEDIUM",
    "REQUEST_INSTALL_PACKAGES": "HIGH", "GET_USAGE_STATS": "HIGH", "READ_CLIPBOARD": "MEDIUM",
    "POST_NOTIFICATION": "LOW", "WAKE_LOCK": "LOW",
}
_APPOP_CATEGORY = {
    "SMS": "sms", "CONTACTS": "data_exfil", "CALL": "data_exfil", "PHONE": "data_exfil",
    "LOCATION": "surveillance", "CAMERA": "surveillance", "AUDIO": "surveillance",
    "PROJECT_MEDIA": "surveillance", "ALERT_WINDOW": "overlay", "ACCESSIBILITY": "surveillance",
    "STORAGE": "file_io", "MEDIA": "file_io", "INSTALL": "dropper", "CLIPBOARD": "data_exfil",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_full_dynamic_analysis(
    apk_path: str,
    case_dir: str,
    duration: int = DEFAULT_ANALYSIS_DURATION,
    force_emulator: bool = True,
) -> Dict[str, Any]:
    start_time = datetime.now(timezone.utc)
    result: Dict[str, Any] = {
        "phase": "dynamic", "status": "running", "mode": "unknown", "apk_path": apk_path,
        "started_at": start_time.isoformat(), "completed_at": None, "duration_seconds": None,
        "total_events": 0, "events": [], "network_activity": [], "risk_score": 0,
        "risk_level": "low", "risk_breakdown": {}, "behaviors": {}, "errors": [],
    }

    dynamic_dir = os.path.join(case_dir, "dynamic_analysis")
    os.makedirs(dynamic_dir, exist_ok=True)
    debug_log = os.path.join(dynamic_dir, "debug.log")

    def log(msg: str) -> None:
        logger.info(msg)
        with open(debug_log, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now()}] {msg}\n")

    _write_status(dynamic_dir, "booting_emulator", "Starting Android emulator")
    serial = emulator_manager.ensure_emulator(log=log) if force_emulator else vm_orchestrator.is_emulator_running()

    if serial:
        with emulator_manager.analysis_lock:
            try:
                emu_result = _run_emulator_analysis(apk_path, case_dir, dynamic_dir, serial, duration, log)
                result.update(emu_result)
                result["mode"] = "emulator"
                result["status"] = "completed"
                _save_report(dynamic_dir, result)
                _write_status(dynamic_dir, "completed", "Emulator analysis finished")
                return result
            except Exception as e:
                log(f"Emulator analysis failed: {e}")
                result["errors"].append(f"Emulator analysis failed: {e}")
    else:
        result["errors"].append(
            "No Android emulator could be started (check Android SDK emulator + AVD). "
            "Falling back to code-level heuristic scan."
        )

    # ── Layer 2: heuristic code scan (clearly labelled, not runtime data) ──
    _write_status(dynamic_dir, "heuristic", "Running heuristic code scan")
    try:
        h = heuristic_analyzer.run_heuristic_analysis(case_dir)
        result["mode"] = "heuristic"
        result["status"] = h.get("status", "completed")
        for key in ("events", "network_activity", "total_events", "risk_score", "risk_level",
                    "risk_breakdown", "behaviors"):
            if key in h:
                result[key] = h[key]
    except Exception as e:
        log(f"Heuristic analysis failed: {e}")
        result["errors"].append(str(e))
        result["status"] = "failed"

    end_time = datetime.now(timezone.utc)
    result["completed_at"] = end_time.isoformat()
    result["duration_seconds"] = (end_time - start_time).total_seconds()
    _save_report(dynamic_dir, result)
    _write_status(dynamic_dir, result["status"], "Finished")
    return result


def _load_static(case_dir: str) -> Dict[str, Any]:
    path = os.path.join(case_dir, "static_analysis", "static_report.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _static_hosts(static: Dict[str, Any]) -> set:
    iocs = static.get("steps", {}).get("iocs", {}).get("data", {}) or {}
    hosts = set(d.lower() for d in iocs.get("domains", []) or [])
    for url in iocs.get("urls", []) or []:
        m = re.match(r"\w+://([^/:?#]+)", url)
        if m:
            hosts.add(m.group(1).lower())
    hosts.update(iocs.get("ips", []) or [])
    return hosts


def _run_emulator_analysis(apk_path, case_dir, dynamic_dir, device, duration, log) -> Dict[str, Any]:
    start_time = datetime.now(timezone.utc)
    events: List[Dict[str, Any]] = []
    errors: List[str] = []
    static = _load_static(case_dir)

    manifest = static.get("steps", {}).get("manifest", {}).get("data", {}) or {}
    package_name = manifest.get("package_name") if manifest.get("package_name") not in (None, "", "unknown") else None
    package_name = package_name or vm_orchestrator.get_package_name(apk_path)
    if not package_name:
        raise Exception("Could not determine package name from APK")
    log(f"Dynamic analysis for {package_name} on {device}")

    baseline_pkgs = emulator_manager.list_third_party_packages(device) - {package_name}

    # 1. Install
    _write_status(dynamic_dir, "installing", f"Installing {package_name}")
    install = vm_orchestrator.install_apk(apk_path, package_name, device=device)
    if not install["success"]:
        raise Exception(f"Install failed: {install.get('error') or install.get('stdout')}")
    uid = emulator_manager.get_app_uid(package_name, device)
    if uid is None:
        raise Exception("Installed app UID not found")
    log(f"Installed; app uid={uid}")
    events.append(_evt("install", "system", "Application Installed", package_name, "LOW",
                       f"Installed on {device} (uid {uid})", "orchestrator"))
    traffic_before = emulator_manager.get_uid_traffic(uid, device)

    # 2. Enable declared accessibility services (banking trojans gate behaviour on this)
    a11y = [s.get("name") for s in manifest.get("services", []) or []
            if s.get("permission") == "android.permission.BIND_ACCESSIBILITY_SERVICE" and s.get("name")]
    if a11y:
        comps = ":".join(f"{package_name}/{n}" for n in a11y)
        vm_orchestrator._run_adb(["shell", "settings", "put", "secure", "enabled_accessibility_services", comps], device=device)
        vm_orchestrator._run_adb(["shell", "settings", "put", "secure", "accessibility_enabled", "1"], device=device)
        events.append(_evt("a11y", "surveillance", "Accessibility Service Enabled", package_name, "HIGH",
                           f"Granted to: {', '.join(a11y)}", "orchestrator"))

    # 3. Packet capture + logcat reset
    pcap_path = os.path.abspath(os.path.join(dynamic_dir, "capture.pcap"))
    if os.path.exists(pcap_path):
        os.remove(pcap_path)
    cap = vm_orchestrator._run_adb(["emu", "network", "capture", "start", pcap_path], device=device)
    pcap_started = cap["success"] and "OK" in cap["stdout"]
    if not pcap_started:
        errors.append(f"Packet capture unavailable: {cap.get('error') or cap.get('stdout')}")
    vm_orchestrator._run_adb(["logcat", "-b", "all", "-c"], device=device)

    # 4. Poll sockets owned by the app UID — and by any child app it installs — for the whole run
    sockets: Dict[str, Dict[str, Any]] = {}
    stop = threading.Event()
    tracked_uids: Dict[int, str] = {uid: package_name}   # uid -> package
    child_apps: Dict[str, Dict[str, Any]] = {}            # package -> info
    poll_round = [0]

    def discover_children():
        new_pkgs = emulator_manager.list_third_party_packages(device) - baseline_pkgs - {package_name}
        for pkg in new_pkgs:
            if pkg in child_apps:
                continue
            cuid = emulator_manager.get_app_uid(pkg, device)
            child_apps[pkg] = {"package": pkg, "uid": cuid, "detected_at": _now(), "connections": 0}
            if cuid is not None:
                tracked_uids[cuid] = pkg
            log(f"Child app detected: {pkg} (uid {cuid}) — now tracking its network")

    def poll():
        while not stop.is_set():
            if poll_round[0] % 3 == 0:  # package list is costlier; check every ~6s
                try:
                    discover_children()
                except Exception as e:
                    log(f"Child discovery error: {e}")
            poll_round[0] += 1
            for tuid, tpkg in list(tracked_uids.items()):
                for s in emulator_manager.snapshot_uid_sockets(tuid, device):
                    key = f"{tpkg}|{s['ip']}:{s['port']}:{s['protocol']}"
                    if key not in sockets:
                        sockets[key] = {**s, "first_seen": _now(), "package": tpkg,
                                        "apk_type": "parent" if tpkg == package_name else "child"}
                        if tpkg in child_apps:
                            child_apps[tpkg]["connections"] += 1
                    sockets[key]["last_seen"] = _now()
            stop.wait(NETWORK_POLL_INTERVAL)

    poller = threading.Thread(target=poll, daemon=True)
    poller.start()

    # 4b. Frida instrumentation (SSL unpinning + sensitive-API monitoring).
    # Spawns the app with hooks already in place; falls back to a normal launch.
    frida = None
    frida_launched = False
    if os.environ.get("APEX_ENABLE_FRIDA", "1") == "1":
        try:
            from app.engines.dynamic.frida_manager import FridaManager
            frida = FridaManager(device, package_name)
            if frida.is_available() and frida.check_root() and frida.setup_frida_server():
                # apex_monitor.js is stable across apps; the heavier SSL-interception
                # script can destabilise some apps, so it is opt-in via APEX_FRIDA_SSL.
                scripts = ["apex_monitor.js"]
                if os.environ.get("APEX_FRIDA_SSL", "0") == "1":
                    scripts.append("ssl_network_hooks.js")
                frida_launched = frida.spawn_and_inject(scripts)
                if frida_launched:
                    log("Frida instrumentation active")
                    events.append(_evt("frida", "system", "Instrumentation Attached", package_name,
                                       "LOW", "Frida hooks active (SSL unpinning + API monitor)", "frida_runtime"))
            if not frida_launched:
                log("Frida unavailable; continuing with uninstrumented execution")
        except Exception as e:
            log(f"Frida setup failed: {e}")
            errors.append(f"Frida unavailable: {e}")
            frida = None

    stimuli: List[str] = []
    exploration: Dict[str, Any] = {}
    try:
        # 5. Launch + exercise
        _write_status(dynamic_dir, "running", f"Executing {package_name} for {duration}s")
        if not frida_launched:
            vm_orchestrator.launch_app(package_name, device=device)
        events.append(_evt("launch", "system", "Application Started", package_name, "LOW",
                           "App launched by orchestrator", "orchestrator"))
        time.sleep(5)
        # Feed external stimuli so trigger-based malware runs its payload
        try:
            stimuli = emulator_manager.simulate_events(device, package_name, log=log)
            if stimuli:
                events.append(_evt("stimuli", "system", "External Stimuli Injected", package_name, "LOW",
                                   "Delivered: " + ", ".join(stimuli), "orchestrator"))
        except Exception as e:
            log(f"Stimuli injection failed: {e}")
        deadline = time.time() + duration
        # UI-aware exploration first (fills forms, taps buttons, backtracks), monkey for the rest
        try:
            explore_secs = max(20, duration // 2)
            exploration = ui_explorer.explore(package_name, device=device, duration=explore_secs, log=log)
            events.append(_evt("ui_exploration", "system", "UI Exploration", package_name, "LOW",
                               f"Visited {exploration.get('screens_visited', 0)} screens / "
                               f"{len(exploration.get('activities_seen', []))} activities, "
                               f"{exploration.get('taps', 0)} taps, {exploration.get('text_fields_filled', 0)} fields filled", "orchestrator"))
        except Exception as e:
            log(f"UI exploration failed: {e}")
        rounds = 0
        while time.time() < deadline - 5:
            rounds += 1
            remaining = int(deadline - time.time())
            n = max(50, min(600, remaining * 8))
            vm_orchestrator.run_monkey(package_name, events=n, device=device)
            if rounds == 2:  # re-deliver SMS/location once the app's UI is up
                try:
                    emulator_manager.simulate_events(device, package_name, log=log)
                except Exception:
                    pass
            # Bring the app back to the foreground if the monkey navigated away / it crashed
            if not vm_orchestrator._run_adb(["shell", "pidof", package_name], device=device)["stdout"].strip():
                vm_orchestrator.launch_app(package_name, device=device)
            time.sleep(2)
        log(f"Exercised app with {rounds} monkey rounds")
        time.sleep(3)
    finally:
        stop.set()
        poller.join(timeout=10)
        if pcap_started:
            vm_orchestrator._run_adb(["emu", "network", "capture", "stop"], device=device)

    # 5b. Collect Frida runtime evidence before teardown
    frida_network: List[Dict[str, Any]] = []
    if frida:
        try:
            for fe in frida.to_behavior_events():
                if fe.get("api_call") not in {e.get("api_call") for e in events}:
                    events.append(fe)
            frida_network = frida.to_network_activity()
            frida.detach()
        except Exception as e:
            log(f"Frida collection failed: {e}")

    # 6. Logs scoped to the app
    _write_status(dynamic_dir, "collecting", "Collecting evidence")
    app_log = vm_orchestrator._run_adb(["logcat", "-d", "-v", "threadtime", "--uid", str(uid)], device=device, timeout=60)["stdout"]
    full_log = vm_orchestrator._run_adb(["logcat", "-b", "all", "-d", "-v", "threadtime"], device=device, timeout=60)["stdout"]
    system_lines = "\n".join(l for l in full_log.splitlines()
                             if package_name in l and l not in app_log)
    with open(os.path.join(dynamic_dir, "logcat.txt"), "w", encoding="utf-8") as f:
        f.write(app_log + "\n\n# ---- system lines referencing package ----\n" + system_lines)

    # Generic patterns only on the app's own log: system logs mention many unrelated URLs
    for e in vm_orchestrator.parse_logcat_events(app_log, package_name):
        if e["source"] != "orchestrator":
            events.append(e)
    events.extend(_parse_system_events(system_lines, package_name))

    # 7. AppOps actually exercised + running components
    for op in emulator_manager.get_appops_usage(package_name, device):
        name = op["op"]
        risk = _APPOP_RISK.get(name)
        if not risk:
            continue
        cat = next((c for k, c in _APPOP_CATEGORY.items() if k in name), "permission")
        events.append(_evt(f"appop-{name}", cat, f"Runtime Access: {name}", package_name, risk,
                           f"mode={op['mode']} {op['detail']}", "appops_runtime"))
    comps = emulator_manager.get_running_components(package_name, device)
    for svc in comps["running_services"]:
        events.append(_evt(f"svc-{svc}", "persistence", "Background Service Running", package_name, "MEDIUM",
                           svc, "dumpsys_runtime"))

    # 8. Dropped / silently installed packages — profile each child app
    try:
        discover_children()  # catch anything installed after the last poll
    except Exception:
        pass
    dropped = sorted(set(child_apps) | (emulator_manager.list_third_party_packages(device) - baseline_pkgs - {package_name}))
    for pkg in dropped:
        info = child_apps.setdefault(pkg, {"package": pkg, "uid": emulator_manager.get_app_uid(pkg, device),
                                           "detected_at": _now(), "connections": 0})
        events.append(_evt(f"drop-{pkg}", "dropper", "Child APK Installed", pkg, "CRITICAL",
                           f"Package {pkg} was installed during execution", "package_diff"))
        try:
            info.update(_profile_child(pkg, info.get("uid"), device, dynamic_dir, events))
        except Exception as e:
            info["error"] = str(e)
            log(f"Child profiling failed for {pkg}: {e}")

    # 9. Network: UID-attributed sockets enriched with packet capture
    pcap = {}
    if pcap_started and os.path.exists(pcap_path):
        pcap = _analyze_pcap(pcap_path)
    network_activity = _build_network(sockets, pcap, _static_hosts(static))
    # Merge Frida-intercepted HTTP(S) endpoints (URLs seen even under TLS)
    net_keys = {(n.get("destination"), str(n.get("port"))) for n in network_activity}
    for fn in frida_network:
        k = (fn.get("destination") or fn.get("hostname"), str(fn.get("port")))
        if k[0] and k not in net_keys:
            fn.setdefault("source", "frida_intercept")
            fn.setdefault("direction", "OUTBOUND")
            network_activity.append(fn)
            net_keys.add(k)
    for n in network_activity:
        events.append(_evt(f"net-{n['ip']}-{n['port']}", "network",
                           "DNS Query" if n["source"] == "dns_capture" else "Network Connection",
                           package_name, "MEDIUM", f"{n['destination']}:{n['port']} ({n['protocol']})",
                           n["source"]))
    traffic_after = emulator_manager.get_uid_traffic(uid, device)
    traffic = {k: max(0, traffic_after[k] - traffic_before[k]) for k in traffic_after}

    # Crash detection
    crashed = "FATAL EXCEPTION" in app_log or f"Process {package_name}" in system_lines and "has died" in system_lines

    # Leave the sandbox clean for the next sample
    if os.environ.get("APEX_KEEP_INSTALLED", "0") != "1":
        for pkg in [package_name] + dropped:
            vm_orchestrator.uninstall_apk(pkg, device=device)

    risk = heuristic_analyzer.compute_heuristic_risk(events)
    end_time = datetime.now(timezone.utc)
    events.append(_evt("end", "system", "Analysis Complete", package_name, "LOW",
                       "Automated execution finished", "orchestrator"))

    return {
        "started_at": start_time.isoformat(),
        "completed_at": end_time.isoformat(),
        "duration_seconds": (end_time - start_time).total_seconds(),
        "package_name": package_name,
        "device": device,
        "app_uid": uid,
        "frida_active": frida_launched,
        "stimuli_injected": stimuli,
        "ui_exploration": exploration,
        "total_events": len(events),
        "events": events,
        "network_activity": network_activity,
        "traffic": traffic,
        "dns_queries": sorted(pcap.get("dns", {}).keys()) if pcap else [],
        "pcap_file": "capture.pcap" if pcap_started else None,
        "dropped_packages": dropped,
        "child_apps": [
            {**info, "network": [n for n in network_activity if n.get("attributed_package") == pkg]}
            for pkg, info in child_apps.items()
        ],
        "running_services": comps["running_services"],
        "app_crashed": crashed,
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"],
        "risk_breakdown": risk["risk_breakdown"],
        "behaviors": risk["behaviors"],
        "errors": errors,
    }


def _profile_child(pkg: str, cuid: Optional[int], device: str, dynamic_dir: str,
                   events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Collect runtime + static evidence for an app installed by the analysed sample."""
    out: Dict[str, Any] = {}
    child_dir = os.path.join(dynamic_dir, "child_apps", pkg)
    os.makedirs(child_dir, exist_ok=True)

    # Its own log lines
    if cuid is not None:
        clog = vm_orchestrator._run_adb(["logcat", "-d", "-v", "threadtime", "--uid", str(cuid)],
                                        device=device, timeout=60)["stdout"]
        with open(os.path.join(child_dir, "logcat.txt"), "w", encoding="utf-8") as f:
            f.write(clog)
        for e in vm_orchestrator.parse_logcat_events(clog, pkg):
            if e["source"] != "orchestrator":
                e["source_package"] = pkg
                e["apk_type"] = "child"
                events.append(e)

    # Sensitive operations it actually performed
    used_ops = []
    for op in emulator_manager.get_appops_usage(pkg, device):
        risk = _APPOP_RISK.get(op["op"])
        if risk:
            used_ops.append(op["op"])
            cat = next((c for k, c in _APPOP_CATEGORY.items() if k in op["op"]), "permission")
            ev = _evt(f"child-appop-{pkg}-{op['op']}", cat, f"Child Runtime Access: {op['op']}", pkg, risk,
                      f"{pkg}: mode={op['mode']} {op['detail']}", "appops_runtime")
            ev["source_package"] = pkg
            ev["apk_type"] = "child"
            events.append(ev)
    out["runtime_ops"] = used_ops
    out["running_services"] = emulator_manager.get_running_components(pkg, device)["running_services"]

    # Pull the child APK and profile it statically
    path_out = vm_orchestrator._run_adb(["shell", "pm", "path", pkg], device=device)["stdout"]
    base = next((l.split(":", 1)[1].strip() for l in path_out.splitlines() if l.startswith("package:")), None)
    if base:
        local_apk = os.path.join(child_dir, f"{pkg}.apk")
        if vm_orchestrator._run_adb(["pull", base, local_apk], device=device, timeout=120)["success"]:
            import hashlib
            with open(local_apk, "rb") as f:
                out["sha256"] = hashlib.sha256(f.read()).hexdigest()
            out["apk_file"] = os.path.relpath(local_apk, dynamic_dir)
            try:
                from androguard.core.apk import APK
                a = APK(local_apk)
                perms = sorted(set(a.get_permissions()))
                dangerous = [p for p in perms if any(k in p for k in (
                    "SMS", "CONTACTS", "CALL_LOG", "LOCATION", "CAMERA", "RECORD_AUDIO", "READ_PHONE",
                    "ACCESSIBILITY", "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES", "BIND_DEVICE_ADMIN"))]
                out.update({
                    "app_name": a.get_app_name(),
                    "version": a.get_androidversion_name(),
                    "permissions": perms,
                    "dangerous_permissions": dangerous,
                })
            except Exception as e:
                out["static_error"] = str(e)
    return out


_SYSTEM_PATTERNS = [
    (r"wm_create_activity: \[[^\]]*?,(?P<pkg>[\w\.]+)/(?P<c>[\w\.\$]+)", "ui", "Activity Launched", "LOW"),
    (r"am_create_service: \[[^\]]*?(?P<pkg>[\w\.]+)/(?P<c>[\w\.\$]+)", "persistence", "Service Started", "MEDIUM"),
    (r"am_proc_start: \[[^\]]*?,(?P<pkg>[\w\.]+),(?P<c>broadcast|service|content provider)", "persistence", "Process Started In Background", "MEDIUM"),
    (r"Permission Denial: (?P<c>.+)", "security", "Permission Denial", "HIGH"),
    (r"am_crash: \[[^\]]*?(?P<pkg>[\w\.]+),[^,]*,(?P<c>[\w\.]+Exception)", "crash", "Application Crash", "MEDIUM"),
    (r"am_anr: \[[^\]]*?(?P<pkg>[\w\.]+),(?P<c>.*)", "crash", "Application Not Responding", "LOW"),
    (r"(?P<c>DeviceAdmin\w*|device_admin.*)", "persistence", "Device Admin Interaction", "CRITICAL"),
    (r"Sending SMS|SmsManager.*(?P<c>sendTextMessage|sendMultipartTextMessage)", "sms", "SMS Sent", "CRITICAL"),
]


def _parse_system_events(lines: str, package_name: str) -> List[Dict[str, Any]]:
    """Runtime facts emitted by system_server about the analysed package."""
    out, seen = [], set()
    for line in lines.splitlines():
        for pat, cat, title, risk in _SYSTEM_PATTERNS:
            m = re.search(pat, line)
            if not m:
                continue
            gd = m.groupdict()
            if gd.get("pkg") and gd["pkg"] != package_name:
                continue
            if "pkg" not in gd and package_name not in line:
                continue
            detail = (gd.get("c") or m.group(0)).strip()
            key = (title, detail[:80])
            if key in seen:
                continue
            seen.add(key)
            ts = re.match(r"(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)", line)
            e = _evt(f"sys-{len(out)}", cat, title, package_name, risk, detail, "system_server_runtime")
            if ts:
                e["timestamp"] = ts.group(1)
            e["raw_line"] = line[:300]
            out.append(e)
    return out


def _evt(eid, category, title, cls, risk, desc, source) -> Dict[str, Any]:
    return {"id": f"rt-{eid}", "timestamp": _now(), "category": category, "api_call": title,
            "class_name": cls, "risk_level": risk, "description": str(desc)[:300], "source": source}


def _tls_sni(payload: bytes) -> Optional[str]:
    """Extract SNI from a TLS ClientHello."""
    try:
        if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
            return None
        p = 43
        p += 1 + payload[p]                                     # session id
        p += 2 + int.from_bytes(payload[p:p + 2], "big")       # cipher suites
        p += 1 + payload[p]                                     # compression
        end = p + 2 + int.from_bytes(payload[p:p + 2], "big")
        p += 2
        while p + 4 <= end:
            etype = int.from_bytes(payload[p:p + 2], "big")
            elen = int.from_bytes(payload[p + 2:p + 4], "big")
            if etype == 0:
                nlen = int.from_bytes(payload[p + 7:p + 9], "big")
                return payload[p + 9:p + 9 + nlen].decode("ascii", "replace")
            p += 4 + elen
    except Exception:
        return None
    return None


def _analyze_pcap(path: str) -> Dict[str, Any]:
    """DNS answers, TLS SNI and per-remote-IP byte counts from the emulator capture."""
    out: Dict[str, Any] = {"dns": {}, "sni": {}, "bytes": {}, "http_hosts": {}}
    try:
        from scapy.all import PcapReader, IP, IPv6, TCP, UDP, DNS, DNSQR, Raw, conf
        conf.verb = 0
        for pkt in PcapReader(path):
            ip = pkt[IP] if IP in pkt else (pkt[IPv6] if IPv6 in pkt else None)
            if ip is None:
                continue
            src, dst = str(ip.src), str(ip.dst)
            outbound = src.startswith(("10.0.2.", "fec0:", "fe80:"))  # emulator's own v4/v6 addresses
            remote = dst if outbound else src
            b = out["bytes"].setdefault(remote, {"sent": 0, "recv": 0, "packets": 0})
            b["sent" if outbound else "recv"] += len(pkt)
            b["packets"] += 1
            if DNS in pkt and DNSQR in pkt:
                q = pkt[DNSQR].qname.decode("utf-8", "replace").rstrip(".").lower()
                answers = out["dns"].setdefault(q, [])
                d = pkt[DNS]
                for i in range(d.ancount or 0):
                    try:
                        rr = d.an[i]
                        if rr.type in (1, 28) and str(rr.rdata) not in answers:
                            answers.append(str(rr.rdata))
                    except Exception:
                        pass
            elif TCP in pkt and Raw in pkt and outbound:
                data = bytes(pkt[Raw].load)
                sni = _tls_sni(data)
                if sni:
                    out["sni"][dst] = sni
                elif data[:4] in (b"GET ", b"POST", b"PUT ", b"HEAD"):
                    m = re.search(rb"\r\nHost:\s*([^\r\n]+)", data)
                    if m:
                        out["http_hosts"][dst] = m.group(1).decode("ascii", "replace")
    except Exception as e:
        logger.warning(f"PCAP analysis failed: {e}")
    return out


def _build_network(sockets: Dict[str, Dict], pcap: Dict[str, Any], static_hosts: set) -> List[Dict[str, Any]]:
    ip_to_name: Dict[str, str] = {}
    for name, ips in pcap.get("dns", {}).items():
        for ip in ips:
            ip_to_name.setdefault(ip, name)
    ip_to_name.update(pcap.get("http_hosts", {}))
    ip_to_name.update(pcap.get("sni", {}))

    network: List[Dict[str, Any]] = []
    seen_hosts = set()
    for s in sockets.values():
        ip = s["ip"]
        if ip.startswith(("10.0.2.", "fec0:", "fe80:")):  # emulator gateway / DNS proxy
            continue
        host = ip_to_name.get(ip, "")
        seen_hosts.add(host)
        b = pcap.get("bytes", {}).get(ip, {})
        network.append({
            "destination": host or ip, "hostname": host, "ip": ip, "port": str(s["port"]),
            "protocol": "HTTPS" if s["port"] == 443 else ("HTTP" if s["port"] == 80 else s["protocol"]),
            "direction": "OUTBOUND", "state": s.get("state"),
            "bytes_sent": b.get("sent", 0), "bytes_received": b.get("recv", 0), "packets": b.get("packets", 0),
            "first_seen": s.get("first_seen"), "last_seen": s.get("last_seen"),
            "source": "runtime_capture", "static_reference": host in static_hosts or ip in static_hosts,
            "attributed_package": s.get("package"), "source_package": s.get("package"),
            "apk_type": s.get("apk_type", "parent"),
        })
    # Lookups for hosts the APK hardcodes but that never produced a socket (e.g. dead C2)
    for name, ips in pcap.get("dns", {}).items():
        if name in static_hosts and name not in seen_hosts:
            network.append({
                "destination": name, "hostname": name, "ip": ", ".join(ips) or "NXDOMAIN",
                "port": "53", "protocol": "DNS", "direction": "OUTBOUND", "source": "dns_capture",
                "static_reference": True, "bytes_sent": 0, "bytes_received": 0, "packets": 0,
            })
    return network


def _write_status(dynamic_dir: str, stage: str, message: str) -> None:
    try:
        with open(os.path.join(dynamic_dir, "status.json"), "w") as f:
            json.dump({"stage": stage, "message": message, "updated_at": _now()}, f)
    except Exception:
        pass


def _save_report(dynamic_dir: str, result: Dict[str, Any]) -> None:
    try:
        with open(os.path.join(dynamic_dir, "dynamic_report.json"), "w") as f:
            json.dump(result, f, indent=2, default=str)
    except Exception as e:
        logger.error(f"Failed to save dynamic report: {e}")
