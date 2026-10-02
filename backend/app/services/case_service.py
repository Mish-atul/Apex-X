"""
Case-level helpers — notably the overall threat score, aggregated across
analysis phases with evidence-based floors so confirmed malware always reads
as high-risk even when individual phase scorers under-count it.
"""

import re
from typing import Iterable, Any

# Family keywords that indicate a confirmed-malicious attribution
_MALWARE_FAMILY_RE = re.compile(
    r"trojan|dropper|spy|bank|rat\b|stealer|ransom|agent|smsthief|fakeapp|phish|botnet|backdoor",
    re.IGNORECASE,
)


def _is_malware_family(name: Any) -> bool:
    if not name:
        return False
    n = str(name).strip().lower()
    if n in ("", "unknown", "benign", "none", "clean"):
        return False
    return bool(_MALWARE_FAMILY_RE.search(n))


def compute_threat_score(phase_results: Iterable[Any]) -> int:
    """
    Overall case threat score (0-100).

    Base = highest individual phase risk score. Then apply evidence floors:
      * a confirmed malware-family attribution (C2 intelligence) floors at 85
      * a dropped/child APK observed at runtime floors at 90
    This prevents confirmed malware from reading low just because its danger
    lives in behaviour/attribution rather than OWASP misconfig findings.
    """
    phases = list(phase_results)
    scores = [getattr(p, "risk_score", None) for p in phases]
    base = max([s for s in scores if s is not None], default=0)

    floor = 0
    for p in phases:
        result = getattr(p, "result", None) or {}
        phase = getattr(p, "phase", "")
        if phase == "c2_intelligence":
            attribution = (result.get("attribution") or {})
            family = attribution.get("malware_family") or attribution.get("family")
            if _is_malware_family(family):
                floor = max(floor, 85)
        if phase == "dynamic":
            if result.get("dropped_packages"):
                floor = max(floor, 90)

    return int(max(base, floor))
