"""
Quark-Engine integration — rule-based Android malware behaviour scoring
(https://github.com/quark-engine/quark-engine).

Runs the `quark` CLI against the APK with the quark-rules set (downloaded via
`freshquark`) and returns the threat level, total score and the top matched
behaviours ("crimes") sorted by confidence.
"""

import os
import sys
import json
import shutil
import logging
import tempfile
import subprocess
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

QUARK_TIMEOUT = int(os.environ.get("APEX_QUARK_TIMEOUT", "600"))
TOP_N = int(os.environ.get("APEX_QUARK_TOP_N", "25"))


def _tool(name: str) -> Optional[str]:
    exe = shutil.which(name)
    if exe:
        return exe
    candidate = os.path.join(os.path.dirname(sys.executable), f"{name}.exe" if os.name == "nt" else name)
    return candidate if os.path.isfile(candidate) else None


def _rules_dir() -> Optional[str]:
    env = os.environ.get("APEX_QUARK_RULES")
    candidates = [env] if env else []
    candidates.append(os.path.join(os.path.expanduser("~"), ".quark-engine", "quark-rules", "rules"))
    for c in candidates:
        if c and os.path.isdir(c):
            return c
    return None


def _ensure_rules() -> Optional[str]:
    rules = _rules_dir()
    if rules:
        return rules
    fresh = _tool("freshquark")
    if fresh:
        try:
            subprocess.run([fresh], capture_output=True, text=True, timeout=300)
        except Exception as e:  # noqa: BLE001
            logger.warning(f"freshquark failed: {e}")
    return _rules_dir()


def _conf(c: Dict[str, Any]) -> int:
    try:
        return int(str(c.get("confidence", "0")).rstrip("%"))
    except ValueError:
        return 0


def scan_apk(apk_path: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "available": False, "threat_level": None, "total_score": 0.0,
        "rules_matched": 0, "rules_total": 0, "top_behaviours": [], "labels": {},
    }
    quark = _tool("quark")
    if not quark:
        out["error"] = "Quark-Engine not installed (pip install quark-engine)"
        return out
    rules = _ensure_rules()
    if not rules:
        out["error"] = "Quark rules not found; run `freshquark` or set APEX_QUARK_RULES"
        return out
    out["available"] = True

    fd, json_path = tempfile.mkstemp(suffix=".json", prefix="quark_")
    os.close(fd)
    try:
        try:
            proc = subprocess.run([quark, "-a", apk_path, "-r", rules, "-o", json_path, "-s"],
                                  capture_output=True, text=True, timeout=QUARK_TIMEOUT,
                                  encoding="utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            out["error"] = f"Quark-Engine timed out after {QUARK_TIMEOUT}s"
            return out
        if not os.path.getsize(json_path):
            out["error"] = f"Quark-Engine produced no output (exit {proc.returncode}): {(proc.stderr or '')[-300:]}"
            return out
        with open(json_path, encoding="utf-8") as f:
            report = json.load(f)
    finally:
        try:
            os.remove(json_path)
        except OSError:
            pass

    crimes: List[Dict[str, Any]] = report.get("crimes", []) or []
    matched = [c for c in crimes if _conf(c) > 0]
    # Quark's weighted score: sum of per-rule weights (JSON total_score may be 0)
    total = sum(float(c.get("weight") or 0) for c in crimes)
    out["threat_level"] = report.get("threat_level")
    out["total_score"] = round(report.get("total_score") or total, 3)
    out["rules_total"] = len(crimes)
    out["rules_matched"] = len(matched)
    out["high_confidence"] = sum(1 for c in matched if _conf(c) >= 80)

    labels: Dict[str, int] = {}
    for c in matched:
        if _conf(c) >= 80:
            for lb in c.get("label") or []:
                labels[lb] = labels.get(lb, 0) + 1
    out["labels"] = dict(sorted(labels.items(), key=lambda kv: -kv[1]))

    matched.sort(key=lambda c: (_conf(c), float(c.get("score") or 0)), reverse=True)
    out["top_behaviours"] = [{
        "rule": c.get("rule"),
        "crime": c.get("crime"),
        "confidence": _conf(c),
        "score": c.get("score"),
        "weight": c.get("weight"),
        "labels": c.get("label") or [],
        "permissions": c.get("permissions") or [],
    } for c in matched[:TOP_N]]
    return out
