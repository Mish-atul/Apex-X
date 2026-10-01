"""
C2 Intelligence Engine — Orchestrator
Extracts IOCs from prior analysis phases, builds the threat infrastructure
graph, and performs malware family attribution.
"""

import os
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any

from app.engines.c2 import graph_builder
from app.engines import virustotal_client

logger = logging.getLogger(__name__)


def run_full_c2_intelligence(apk_path: str, case_dir: str, case_id: str) -> Dict[str, Any]:
    """
    Execute the C2 intelligence pipeline.
    Reads static/dynamic reports + deep scan intelligence to build
    the threat graph and attribute the malware.
    """
    start_time = datetime.now(timezone.utc)
    apk_hash = _get_apk_hash(case_dir, apk_path)
    package_name = _get_package_name(case_dir)

    result = {
        "phase": "c2",
        "status": "running",
        "case_id": case_id,
        "started_at": start_time.isoformat(),
        "completed_at": None,
        "duration_seconds": None,
        "nodes": [],
        "edges": [],
        "detection_summary": {},
        "attribution": {},
        "contacted_infrastructure": {},
        "risk_score": 0,
        "errors": [],
    }

    c2_dir = os.path.join(case_dir, "c2_intelligence")
    os.makedirs(c2_dir, exist_ok=True)

    # ── Step 1: Build Graph ──
    logger.info("C2 Phase - Step 1: Building threat infrastructure graph")
    try:
        graph_result = graph_builder.build_c2_graph(
            case_dir=case_dir,
            apk_hash=apk_hash,
            package_name=package_name,
        )
        result["nodes"] = graph_result.get("nodes", [])
        result["edges"] = graph_result.get("edges", [])
        result["detection_summary"] = graph_result.get("detection_summary", {})
        result["contacted_infrastructure"] = {
            "domains": graph_result.get("domains", []),
            "ips": graph_result.get("ips", []),
            "urls": graph_result.get("urls", []),
            "dropped_files": graph_result.get("dropped_files_count", 0),
        }
    except Exception as e:
        logger.error(f"Graph construction failed: {e}")
        result["errors"].append(f"Graph construction error: {e}")

    # ── Step 2: Attribution ──
    logger.info("C2 Phase - Step 2: Malware attribution")
    try:
        detection = result.get("detection_summary", {})
        families = detection.get("malware_families", [])
        verdicts = detection.get("sandbox_verdicts", [])
        popular_name = detection.get("popular_threat_name", "")
        detection_pct = detection.get("detection_percentage", 0)

        # Determine primary family
        primary_family = popular_name or (families[0] if families else "Unknown")

        # Determine threat category from verdicts
        categories = [v.get("category", "") for v in verdicts]
        if "malicious" in categories:
            threat_category = "Confirmed Malicious"
        elif "suspicious" in categories:
            threat_category = "Suspicious"
        else:
            threat_category = "Under Investigation"

        # Determine target region from static analysis
        target_region = _infer_target_region(case_dir)

        # Determine motivation
        motivation = _infer_motivation(case_dir, families)

        result["attribution"] = {
            "malware_family": primary_family,
            "all_families": families[:10],
            "threat_category": threat_category,
            "target_region": target_region,
            "motivation": motivation,
            "confidence": "high" if detection_pct > 50 else "medium" if detection_pct > 20 else "low",
            "detection_ratio": detection.get("detection_ratio", "0/0"),
            "detection_percentage": detection_pct,
            "sandbox_verdicts": verdicts,
            "top_detections": detection.get("top_detections", [])[:10],
            "tags": detection.get("tags", []),
        }

        # Risk score based on detection ratio, infrastructure, and dynamic behavior
        infra = result["contacted_infrastructure"]
        risk = 0
        risk += min(int(detection_pct * 0.6), 60)  # Up to 60 from detection ratio

        # Count non-Google/non-noise IPs as suspicious
        noise_ip_prefixes = ("172.217.", "142.250.", "172.253.", "74.125.", "192.178.", "34.98.", "34.64.", "34.96.", "216.58.")
        all_ips = infra.get("ips", [])
        suspicious_ips = [ip for ip in all_ips if not any(ip.startswith(p) for p in noise_ip_prefixes)]
        
        risk += min(len(suspicious_ips) * 8, 25)  # Up to 25 from suspicious IPs
        risk += min(len(infra.get("domains", [])) * 5, 10)  # Up to 10 from domains
        risk += min(infra.get("dropped_files", 0) * 10, 10)  # Up to 10 from dropped files
        
        # Check for non-standard port connections (strong C2 indicator)
        try:
            from app.models.session import SessionLocal as _SL
            from app.models.database import PhaseResult as _PR
            _normalize = graph_builder._normalize_case_id
            _cuuid = _normalize(case_dir)
            if _cuuid:
                _dbs = _SL()
                try:
                    _dpr = _dbs.query(_PR).filter(_PR.case_id == _cuuid, _PR.phase == "dynamic").first()
                    if _dpr and _dpr.result:
                        _dd = _dpr.result if isinstance(_dpr.result, dict) else json.loads(_dpr.result)
                        for ev in _dd.get("events", []):
                            if isinstance(ev, dict) and ev.get("category") == "network":
                                desc = ev.get("description", "") + ev.get("api_call", "")
                                # Check for non-443/80 ports
                                import re
                                port_match = re.search(r'port\s+(\d+)', desc)
                                if port_match:
                                    port = int(port_match.group(1))
                                    if port not in (80, 443, 8080):
                                        risk += 15  # Non-standard port = strong C2 indicator
                                        if threat_category == "Under Investigation":
                                            threat_category = "Suspicious"
                                            result["attribution"]["threat_category"] = threat_category
                                        break
                finally:
                    _dbs.close()
        except Exception:
            pass

        # Boost confidence if we have dynamic evidence
        if len(all_ips) > 3 and len(suspicious_ips) > 0:
            if result["attribution"]["confidence"] == "low":
                result["attribution"]["confidence"] = "medium"

        result["risk_score"] = min(risk, 100)

    except Exception as e:
        logger.error(f"Attribution failed: {e}")
        result["errors"].append(f"Attribution error: {e}")

    # ── Finalize ──
    end_time = datetime.now(timezone.utc)
    result["completed_at"] = end_time.isoformat()
    result["duration_seconds"] = (end_time - start_time).total_seconds()
    result["status"] = "completed" if not result["errors"] else "completed_with_errors"

    # Save report
    report_path = os.path.join(c2_dir, "c2_report.json")
    try:
        with open(report_path, "w") as f:
            json.dump(result, f, indent=2, default=str)
    except Exception as e:
        logger.error(f"Failed to save C2 report: {e}")

    logger.info(
        f"C2 intelligence complete in {result['duration_seconds']:.1f}s — "
        f"Risk: {result['risk_score']}, Nodes: {len(result['nodes'])}"
    )

    return result


def _get_apk_hash(case_dir: str, apk_path: str = "") -> str:
    """Get SHA-256 hash of the APK."""
    # Try to compute from the APK file
    if apk_path and os.path.exists(apk_path):
        try:
            return virustotal_client.sha256_of_file(apk_path)
        except Exception:
            pass

    # Try from static report
    static_path = os.path.join(case_dir, "static_analysis", "static_report.json")
    if os.path.exists(static_path):
        try:
            with open(static_path, "r") as f:
                report = json.load(f)
            ap = report.get("apk_path", "")
            if ap and os.path.exists(ap):
                return virustotal_client.sha256_of_file(ap)
        except Exception:
            pass

    # Fallback: find any APK in case_dir
    for fname in os.listdir(case_dir):
        if fname.endswith(".apk"):
            return virustotal_client.sha256_of_file(os.path.join(case_dir, fname))

    return "unknown_hash"


def _get_package_name(case_dir: str) -> str:
    """Extract package name from static analysis."""
    for path in [
        os.path.join(case_dir, "static_analysis", "permissions_profile.json"),
        os.path.join(case_dir, "static_analysis", "static_report.json"),
    ]:
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    data = json.load(f)
                pkg = data.get("package_name") or data.get("steps", {}).get("manifest", {}).get("data", {}).get("package_name")
                if pkg:
                    return pkg
            except Exception:
                pass
    return "unknown"


def _infer_target_region(case_dir: str) -> str:
    """Infer target region from static analysis data."""
    static_path = os.path.join(case_dir, "static_analysis", "static_report.json")
    if not os.path.exists(static_path):
        return "Unknown"

    try:
        with open(static_path, "r") as f:
            report = json.load(f)

        # Check for India-specific indicators
        all_text = json.dumps(report).lower()
        if any(w in all_text for w in ["india", "inr", "rupee", "aadhaar", "upi", "rto", "challan", "paytm", "phonepe", "yojana", "awas", "awash", "pradhan", "sarkari", "parivahan", "pm"]):
            return "India"
        if any(w in all_text for w in ["china", "cny", "wechat", "alipay"]):
            return "China"
        if any(w in all_text for w in ["russia", "rub", "yandex"]):
            return "Russia"
        if any(w in all_text for w in ["brazil", "brl", "pix"]):
            return "Brazil"
    except Exception:
        pass
    return "Global"


def _infer_motivation(case_dir: str, families: list) -> str:
    """Infer threat motivation from malware family names and static analysis."""
    family_str = " ".join(families).lower()
    
    if any(w in family_str for w in ["banker", "bank", "trojan", "spy", "stealer"]):
        return "Financial — Banking credential theft"
    if any(w in family_str for w in ["ransom", "locker", "crypt"]):
        return "Extortion — Ransomware"
    if any(w in family_str for w in ["adware", "ads", "click"]):
        return "Revenue — Adware / Click fraud"
    if any(w in family_str for w in ["spy", "stalker", "monitor"]):
        return "Surveillance — Spyware"
    if any(w in family_str for w in ["sms", "premium", "toll"]):
        return "Financial — Premium SMS fraud"
    
    # Check static report for clues
    static_path = os.path.join(case_dir, "static_analysis", "static_report.json")
    if os.path.exists(static_path):
        try:
            with open(static_path, "r") as f:
                text = f.read().lower()
            if "sms" in text and "send" in text:
                return "Financial — SMS-based fraud"
            if "camera" in text or "audio" in text:
                return "Surveillance — Device monitoring"
            if "accessibility" in text:
                return "Financial — Accessibility abuse"
        except Exception:
            pass

    return "Under investigation"
