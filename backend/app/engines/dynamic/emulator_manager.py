"""
Emulator Manager — boots an Android Virtual Device on demand so dynamic
analysis never requires a physical phone or USB cable, and provides
per-app (UID-scoped) runtime evidence collection helpers.
"""

import os
import re
import time
import shutil
import logging
import ipaddress
import subprocess
import threading
from typing import Optional, Dict, Any, List

from app.engines.dynamic.vm_orchestrator import _find_adb, _run_adb, is_emulator_running, wait_for_boot

logger = logging.getLogger(__name__)

EMULATOR_BOOT_TIMEOUT = int(os.environ.get("APEX_EMULATOR_BOOT_TIMEOUT", "600"))
_boot_lock = threading.Lock()
# Only one dynamic run may drive the emulator at a time
analysis_lock = threading.Lock()
_emulator_proc: Optional[subprocess.Popen] = None


def _sdk_root() -> Optional[str]:
    adb = _find_adb()
    if adb:
        return os.path.dirname(os.path.dirname(adb))
    for env in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        if os.environ.get(env):
            return os.environ[env]
    return None


def find_emulator_binary() -> Optional[str]:
    root = _sdk_root()
    if root:
        for name in ("emulator.exe", "emulator"):
            candidate = os.path.join(root, "emulator", name)
            if os.path.isfile(candidate):
                return candidate
    return shutil.which("emulator")


def list_avds() -> List[str]:
    emu = find_emulator_binary()
    if not emu:
        return []
    try:
        out = subprocess.run([emu, "-list-avds"], capture_output=True, text=True, timeout=30).stdout
    except Exception:
        return []
    return [l.strip() for l in out.splitlines()
            if l.strip() and not l.startswith(("INFO", "WARNING", "ERROR"))]


def _pick_avd() -> Optional[str]:
    avds = list_avds()
    preferred = os.environ.get("APEX_AVD_NAME")
    if preferred and preferred in avds:
        return preferred
    for want in ("ApexX_Sandbox", "medium_phone"):
        for name in avds:
            if want.lower() in name.lower():
                return name
    return avds[0] if avds else None


def emulator_status() -> Dict[str, Any]:
    serial = is_emulator_running()
    booted = bool(serial) and _run_adb(["shell", "getprop", "sys.boot_completed"], device=serial)["stdout"].strip() == "1"
    return {
        "sdk_found": bool(_find_adb()),
        "emulator_binary": find_emulator_binary(),
        "avds": list_avds(),
        "serial": serial,
        "booted": booted,
    }


def ensure_emulator(timeout: int = EMULATOR_BOOT_TIMEOUT, log=None) -> Optional[str]:
    """
    Return the serial of a fully booted emulator, launching one if needed.
    Needs only the Android SDK + an AVD — no physical phone or USB.
    """
    global _emulator_proc
    _log = log or logger.info

    with _boot_lock:
        serial = is_emulator_running()
        if serial and wait_for_boot(serial, 10):
            _prepare_device(serial)
            return serial

        if not serial and not is_emulator_running(include_offline=True):
            emu, avd = find_emulator_binary(), _pick_avd()
            if not emu or not avd:
                _log(f"Cannot launch emulator (binary={emu}, avd={avd}). Install the Android SDK emulator and create an AVD.")
                return None
            args = [emu, "-avd", avd, "-no-audio", "-no-boot-anim", "-no-snapshot-save", "-gpu", "auto"]
            if os.environ.get("APEX_EMULATOR_HEADLESS", "0") == "1":
                args.append("-no-window")
            _log(f"Launching emulator: {' '.join(args)}")
            flags = 0
            if os.name == "nt":
                flags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
            _emulator_proc = subprocess.Popen(
                args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL, creationflags=flags, close_fds=True,
            )

        deadline = time.time() + timeout
        serial = None
        while time.time() < deadline:
            serial = is_emulator_running(include_offline=True)
            if serial:
                break
            if _emulator_proc and _emulator_proc.poll() is not None:
                _log(f"Emulator process exited early (code {_emulator_proc.returncode})")
                return None
            time.sleep(2)
        if not serial:
            _log("Emulator never appeared in adb")
            return None

        unauthorized_since = None
        while True:
            if _run_adb(["shell", "getprop", "sys.boot_completed"], device=serial)["stdout"].strip() == "1":
                break
            if f"{serial}\tunauthorized" in _run_adb(["devices"])["stdout"]:
                unauthorized_since = unauthorized_since or time.time()
                if time.time() - unauthorized_since > 90:
                    _log(f"Emulator {serial} is 'unauthorized' for adb. Use a google_apis (non Play Store) "
                         f"AVD such as ApexX_Sandbox, or accept the USB-debugging prompt in the emulator window.")
                    return None
            if time.time() > deadline:
                _log(f"Emulator {serial} did not finish booting within {timeout}s")
                return None
            time.sleep(3)
        for _ in range(30):
            if "package:" in _run_adb(["shell", "pm", "path", "android"], device=serial)["stdout"]:
                break
            time.sleep(2)
        _prepare_device(serial)
        _log(f"Emulator ready: {serial}")
        return serial


def _prepare_device(serial: str) -> None:
    # Root (google_apis images) gives full /proc and logcat visibility; Play images just refuse
    if "cannot run as root" not in _run_adb(["root"], device=serial)["stdout"]:
        time.sleep(3)
        _run_adb(["wait-for-device"], device=serial, timeout=60)
    _run_adb(["shell", "input", "keyevent", "82"], device=serial)  # dismiss keyguard
    _run_adb(["shell", "settings", "put", "global", "package_verifier_enable", "0"], device=serial)
    _run_adb(["shell", "settings", "put", "global", "verifier_verify_adb_installs", "0"], device=serial)
    _run_adb(["shell", "svc", "power", "stayon", "true"], device=serial)


# ── Per-app runtime evidence ────────────────────────────────────────

def get_app_uid(package_name: str, device: Optional[str] = None) -> Optional[int]:
    res = _run_adb(["shell", "pm", "list", "packages", "-U", package_name], device=device)
    for line in res.get("stdout", "").splitlines():
        m = re.match(r"package:(\S+)\s+uid:(\d+)", line.strip())
        if m and m.group(1) == package_name:
            return int(m.group(2))
    res = _run_adb(["shell", "dumpsys", "package", package_name], device=device)
    m = re.search(r"(?:userId|appId)=(\d+)", res.get("stdout", ""))
    return int(m.group(1)) if m else None


def _hex_to_ip(hex_ip: str) -> str:
    if len(hex_ip) == 8:
        return ".".join(str(x) for x in bytes.fromhex(hex_ip)[::-1])
    full = "".join(bytes.fromhex(hex_ip[i:i + 8])[::-1].hex() for i in range(0, 32, 8))
    addr = ipaddress.IPv6Address(bytes.fromhex(full))
    return str(addr.ipv4_mapped) if addr.ipv4_mapped else str(addr)


_TCP_STATES = {"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
               "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
               "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING"}


def snapshot_uid_sockets(uid: int, device: Optional[str] = None) -> List[Dict[str, Any]]:
    """Remote endpoints of sockets owned by `uid` (from /proc/net/{tcp,tcp6,udp,udp6})."""
    out: List[Dict[str, Any]] = []
    for proto in ("tcp", "tcp6", "udp", "udp6"):
        res = _run_adb(["shell", "cat", f"/proc/net/{proto}"], device=device)
        for line in res.get("stdout", "").splitlines()[1:]:
            parts = line.split()
            if len(parts) < 8 or not parts[7].isdigit() or int(parts[7]) != uid:
                continue
            try:
                hex_ip, hex_port = parts[2].split(":")
                ip, port = _hex_to_ip(hex_ip), int(hex_port, 16)
            except Exception:
                continue
            if port == 0 or ip in ("0.0.0.0", "::", "127.0.0.1", "::1"):
                continue
            out.append({"ip": ip, "port": port, "protocol": proto.rstrip("6").upper(),
                        "state": _TCP_STATES.get(parts[3], parts[3])})
    return out


def get_uid_traffic(uid: int, device: Optional[str] = None) -> Dict[str, int]:
    """Total bytes sent/received by uid according to the kernel's per-uid counters."""
    res = _run_adb(["shell", "dumpsys", "netstats", "--uid"], device=device, timeout=45)
    rx = tx = 0
    in_block = False
    for line in res.get("stdout", "").splitlines():
        if "uid=" in line:
            in_block = re.search(rf"\buid={uid}\b", line) is not None
            continue
        if in_block:
            m = re.search(r"rb=(\d+).*?tb=(\d+)", line)
            if m:
                rx += int(m.group(1))
                tx += int(m.group(2))
    return {"bytes_received": rx, "bytes_sent": tx}


def get_appops_usage(package_name: str, device: Optional[str] = None) -> List[Dict[str, str]]:
    """Sensitive operations the app actually performed at runtime (entries with an access time)."""
    res = _run_adb(["shell", "cmd", "appops", "get", package_name], device=device)
    used = []
    for line in res.get("stdout", "").splitlines():
        m = re.match(r"\s*([A-Z_]+):\s*(\w+)(.*)", line)
        if m and ("time=" in m.group(3) or "Access" in m.group(3)):
            used.append({"op": m.group(1), "mode": m.group(2), "detail": m.group(3).strip(" ;")[:200]})
    return used


def get_running_components(package_name: str, device: Optional[str] = None) -> Dict[str, Any]:
    svc = _run_adb(["shell", "dumpsys", "activity", "services", package_name], device=device)
    found = re.findall(rf"ServiceRecord\{{\w+ u\d+ {re.escape(package_name)}/([\w\.\$]+)", svc.get("stdout", ""))
    services = sorted({s for s in found if not re.fullmatch(r"u\d+a\d+", s)})
    pids = _run_adb(["shell", "pidof", package_name], device=device).get("stdout", "").split()
    return {"running_services": services, "pids": pids}


def list_third_party_packages(device: Optional[str] = None) -> set:
    res = _run_adb(["shell", "pm", "list", "packages", "-3"], device=device)
    return {l.split(":", 1)[1].strip() for l in res.get("stdout", "").splitlines() if l.startswith("package:")}


def simulate_events(device: str, package_name: str, log=None) -> List[str]:
    """
    Feed the emulated device realistic external stimuli so malware that waits for a
    trigger (incoming SMS/OTP, a location fix, low battery, connectivity change,
    or a reboot) executes its payload during the analysis window.
    Returns a list of the stimuli that were delivered.
    """
    _log = log or logger.info
    adb = _find_adb()
    done: List[str] = []

    def emu(args: List[str]) -> bool:
        try:
            r = subprocess.run([adb, "-s", device, "emu"] + args,
                               capture_output=True, text=True, timeout=15)
            return "OK" in (r.stdout or "")
        except Exception:
            return False

    if emu(["sms", "send", "3700000001", "Verification code: 847291"]):
        done.append("incoming_sms")
    if emu(["geo", "fix", "-122.084", "37.4220"]):
        done.append("gps_fix")
    if emu(["power", "capacity", "15"]):
        done.append("battery_low")
    # Connectivity drop + restore (some droppers phone home on reconnect)
    if emu(["power", "ac", "off"]) and emu(["power", "ac", "on"]):
        done.append("power_toggle")

    # Broadcasts the app has registered receivers for
    for action in ("android.intent.action.BOOT_COMPLETED",
                   "android.provider.Telephony.SMS_RECEIVED",
                   "android.intent.action.USER_PRESENT"):
        _run_adb(["shell", "am", "broadcast", "-a", action, "-p", package_name], device=device)
    done.append("broadcasts")
    _log(f"Delivered stimuli: {', '.join(done)}")
    return done
