"""
APKiD integration — identifies packers, protectors, obfuscators, compilers and
anti-analysis checks (https://github.com/rednaga/APKiD).

This tells the analyst *why* other results may be thin: a packed APK hides its
real code from static analysis, and anti-VM checks mean emulator results may
understate the app's behaviour.
"""

import os
import sys
import json
import shutil
import logging
import subprocess
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

APKID_TIMEOUT = int(os.environ.get("APEX_APKID_TIMEOUT", "300"))


def _apkid_cmd() -> List[str]:
    exe = shutil.which("apkid")
    if not exe:
        candidate = os.path.join(os.path.dirname(sys.executable), "apkid.exe" if os.name == "nt" else "apkid")
        if os.path.isfile(candidate):
            exe = candidate
    return [exe] if exe else [sys.executable, "-m", "apkid"]


def scan_apk(apk_path: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "packers": [], "protectors": [], "obfuscators": [], "compilers": [],
        "anti_vm": [], "anti_debug": [], "anti_disassembly": [], "manipulators": [],
        "per_file": {},
    }
    try:
        proc = subprocess.run(_apkid_cmd() + ["-j", apk_path], capture_output=True,
                              text=True, timeout=APKID_TIMEOUT)
        data = json.loads(proc.stdout or "{}")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"APKiD timed out after {APKID_TIMEOUT}s")
    except json.JSONDecodeError:
        raise RuntimeError(f"APKiD produced no JSON output: {proc.stderr[-300:]}")

    key_map = {
        "packer": "packers", "protector": "protectors", "obfuscator": "obfuscators",
        "compiler": "compilers", "anti_vm": "anti_vm", "anti_debug": "anti_debug",
        "anti_disassembly": "anti_disassembly", "manipulator": "manipulators",
    }
    for f in data.get("files", []):
        matches = f.get("matches") or {}
        if not matches:
            continue
        name = f.get("filename", "").split("!")[-1] or os.path.basename(apk_path)
        out["per_file"][name] = matches
        for k, v in matches.items():
            bucket = key_map.get(k)
            if bucket:
                for item in v:
                    if item not in out[bucket]:
                        out[bucket].append(item)

    out["is_packed"] = bool(out["packers"] or out["protectors"])
    out["has_anti_analysis"] = bool(out["anti_vm"] or out["anti_debug"] or out["anti_disassembly"])
    notes = []
    if out["is_packed"]:
        notes.append("App is packed/protected — real code is hidden from static analysis; "
                     "runtime (dynamic) evidence is more reliable for this sample.")
    if out["anti_vm"]:
        notes.append("App checks whether it is running in an emulator — dynamic results may "
                     "understate its behaviour.")
    if out["manipulators"]:
        notes.append(f"APK structure is deliberately manipulated ({', '.join(out['manipulators'])}) "
                     "to break analysis tools.")
    out["analyst_notes"] = notes
    return out
