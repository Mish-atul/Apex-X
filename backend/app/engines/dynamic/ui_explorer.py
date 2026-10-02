"""
UI-aware explorer: drives an app through its screens using the uiautomator
view hierarchy instead of random monkey taps. Fills text fields with dummy
data, prefers "progress" buttons (Next/Allow/Login/...), tracks visited
screens/elements, and falls back to back-presses, scrolls and monkey bursts.
"""

import hashlib
import random
import re
import time
import xml.etree.ElementTree as ET
from typing import Any, Callable, Dict, List, Optional, Tuple

from app.engines.dynamic import vm_orchestrator

_BOUNDS = re.compile(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]")

PROGRESS_WORDS = [
    "allow", "accept", "agree", "continue", "next", "ok", "okay", "start", "get started",
    "skip", "login", "log in", "sign in", "sign up", "register", "submit", "done", "yes",
    "confirm", "enable", "grant", "proceed", "got it", "while using", "only this time",
    "activate", "install", "open", "verify", "go",
]
AVOID_WORDS = ["deny", "don't allow", "cancel", "uninstall", "delete", "exit", "quit", "log out", "logout"]

DUMMY = {
    "email": "test@example.com",
    "mail": "test@example.com",
    "pass": "Passw0rd!23",
    "pin": "1234",
    "otp": "123456",
    "code": "123456",
    "phone": "9999999999",
    "mobile": "9999999999",
    "number": "9999999999",
    "name": "Test User",
    "user": "testuser",
    "amount": "100",
}


def _adb(args: List[str], device: str, timeout: int = 20) -> Dict[str, Any]:
    return vm_orchestrator._run_adb(args, device=device, timeout=timeout)


def _dump(device: str) -> Optional[ET.Element]:
    res = _adb(["exec-out", "uiautomator", "dump", "/dev/tty"], device, timeout=25)
    xml = res.get("stdout", "")
    if "<hierarchy" not in xml:
        _adb(["shell", "uiautomator", "dump", "/sdcard/ui.xml"], device, timeout=25)
        xml = _adb(["exec-out", "cat", "/sdcard/ui.xml"], device).get("stdout", "")
    start, end = xml.find("<hierarchy"), xml.rfind("</hierarchy>")
    if start < 0 or end < 0:
        return None
    try:
        return ET.fromstring(xml[start:end + len("</hierarchy>")])
    except ET.ParseError:
        return None


def _center(node: ET.Element) -> Optional[Tuple[int, int]]:
    m = _BOUNDS.match(node.get("bounds", ""))
    if not m:
        return None
    x1, y1, x2, y2 = map(int, m.groups())
    if x2 - x1 < 5 or y2 - y1 < 5:
        return None
    return (x1 + x2) // 2, (y1 + y2) // 2


def _label(node: ET.Element) -> str:
    return " ".join(filter(None, [node.get("text", ""), node.get("content-desc", ""),
                                  node.get("resource-id", "").split("/")[-1]])).strip()


def _key(node: ET.Element) -> str:
    return f"{node.get('resource-id','')}|{node.get('class','')}|{node.get('text','')}|{node.get('content-desc','')}"


def _screen_sig(root: ET.Element) -> str:
    parts = sorted(f"{n.get('class','')}:{n.get('resource-id','')}" for n in root.iter("node"))
    return hashlib.md5("|".join(parts).encode()).hexdigest()[:12]


def _dummy_for(node: ET.Element) -> str:
    hint = (_label(node) + " " + node.get("hint", "")).lower()
    if node.get("password") == "true":
        return DUMMY["pass"]
    for k, v in DUMMY.items():
        if k in hint:
            return v
    return "test"


def _shell_text(s: str) -> str:
    return s.replace(" ", "%s").replace("!", "\\!").replace("@", "\\@").replace("&", "\\&")


def _focused_activity(device: str) -> str:
    out = _adb(["shell", "dumpsys", "window"], device).get("stdout", "")
    m = re.search(r"mCurrentFocus=Window\{[^ ]+ [^ ]+ ([^ }]+)\}", out)
    return m.group(1) if m else ""


def _foreground_pkg(root: ET.Element) -> str:
    for n in root.iter("node"):
        if n.get("package"):
            return n.get("package")
    return ""


def _score(label: str) -> int:
    low = label.lower()
    if any(w in low for w in AVOID_WORDS):
        return -10
    for i, w in enumerate(PROGRESS_WORDS):
        if re.search(r"\b" + re.escape(w) + r"\b", low):
            return 100 - i
    return 1 if label else 0


def explore(package_name: str, device: str, duration: int,
            log: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    """Explore the app's UI for `duration` seconds. Returns coverage stats."""
    log = log or (lambda m: None)
    deadline = time.time() + duration
    screens: set = set()
    clicked: Dict[str, set] = {}
    filled: set = set()
    activities: set = set()
    stats = {"steps": 0, "taps": 0, "text_fields_filled": 0, "back_presses": 0, "relaunches": 0,
             "scrolls": 0, "monkey_fallbacks": 0, "dump_failures": 0}
    stuck = 0
    last_sig = None

    while time.time() < deadline - 3:
        stats["steps"] += 1
        root = _dump(device)
        if root is None:
            stats["dump_failures"] += 1
            if stats["dump_failures"] % 3 == 0:
                stats["monkey_fallbacks"] += 1
                vm_orchestrator.run_monkey(package_name, events=50, device=device)
            time.sleep(1)
            continue

        fg = _foreground_pkg(root)
        system_dialog = fg in ("com.android.permissioncontroller", "com.google.android.permissioncontroller",
                               "android", "com.android.systemui")
        if fg and fg != package_name and not system_dialog:
            if not _adb(["shell", "pidof", package_name], device)["stdout"].strip() or stuck > 2:
                vm_orchestrator.launch_app(package_name, device=device)
                stats["relaunches"] += 1
            else:
                _adb(["shell", "input", "keyevent", "KEYCODE_BACK"], device)
                stats["back_presses"] += 1
            stuck += 1
            time.sleep(1.5)
            continue

        sig = _screen_sig(root)
        if sig not in screens:
            screens.add(sig)
            act = _focused_activity(device)
            if act:
                activities.add(act)
            log(f"UI explorer: new screen {sig} [{act}] ({len(screens)} total)")
        stuck = stuck + 1 if sig == last_sig else 0
        last_sig = sig
        done = clicked.setdefault(sig, set())

        # Fill empty editable fields first
        before = stats["text_fields_filled"]
        for n in root.iter("node"):
            if n.get("class", "").endswith("EditText") and n.get("enabled") == "true":
                k = f"{sig}|{n.get('resource-id','')}|{n.get('bounds','')}"
                c = _center(n)
                if k in filled or not c:
                    continue
                filled.add(k)
                _adb(["shell", "input", "tap", str(c[0]), str(c[1])], device)
                if n.get("text") and n.get("text") != n.get("hint", ""):
                    _adb(["shell", "input", "keyevent", "KEYCODE_MOVE_END"], device)
                    _adb(["shell", "input", "keyevent"] + ["KEYCODE_DEL"] * min(40, len(n.get("text"))), device)
                _adb(["shell", "input", "text", _shell_text(_dummy_for(n))], device)
                stats["text_fields_filled"] += 1
        if stats["text_fields_filled"] > before:
            _adb(["shell", "input", "keyevent", "KEYCODE_ESCAPE"], device)  # hide keyboard (harmless if none)

        candidates = []
        for n in root.iter("node"):
            if n.get("enabled") != "true":
                continue
            if not (n.get("clickable") == "true" or n.get("checkable") == "true"):
                continue
            c = _center(n)
            if not c or _key(n) in done:
                continue
            candidates.append((_score(_label(n)), random.random(), n, c))

        if candidates and stuck < 4:
            candidates.sort(key=lambda t: (t[0], t[1]), reverse=True)
            score, _, node, (x, y) = candidates[0]
            if score >= 0:
                done.add(_key(node))
                _adb(["shell", "input", "tap", str(x), str(y)], device)
                stats["taps"] += 1
                time.sleep(1.2)
                continue

        # Nothing new here: scroll, then back, then monkey burst
        if stuck < 2 and any(n.get("scrollable") == "true" for n in root.iter("node")):
            _adb(["shell", "input", "swipe", "540", "1600", "540", "600", "300"], device)
            stats["scrolls"] += 1
        elif stuck < 5:
            _adb(["shell", "input", "keyevent", "KEYCODE_BACK"], device)
            stats["back_presses"] += 1
        else:
            stats["monkey_fallbacks"] += 1
            vm_orchestrator.run_monkey(package_name, events=80, device=device)
            clicked.pop(sig, None)
            stuck = 0
        time.sleep(1.2)

    stats["screens_visited"] = len(screens)
    stats["activities_seen"] = sorted(activities)
    stats["elements_clicked"] = sum(len(v) for v in clicked.values())
    log(f"UI explorer finished: {stats}")
    return stats
