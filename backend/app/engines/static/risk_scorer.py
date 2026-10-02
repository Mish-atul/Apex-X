"""
Static Risk Scorer — Enhanced
Computes a comprehensive risk score (0-100) based on multiple weighted categories
derived from static analysis findings.
"""

import logging
from typing import Dict, Any, Tuple

logger = logging.getLogger(__name__)

# Scoring weights for each category (total = 100)
CATEGORY_WEIGHTS = {
    "permissions": 25,
    "iocs": 20,
    "yara": 25,
    "api_calls": 15,
    "manifest_misconfig": 15,
}

# Per-permission risk scores
PERMISSION_RISK_SCORES = {
    # Critical data access
    "android.permission.READ_SMS": 8,
    "android.permission.SEND_SMS": 9,
    "android.permission.RECEIVE_SMS": 8,
    "android.permission.READ_CONTACTS": 6,
    "android.permission.READ_CALL_LOG": 7,
    "android.permission.CAMERA": 7,
    "android.permission.RECORD_AUDIO": 8,
    "android.permission.ACCESS_FINE_LOCATION": 6,
    "android.permission.ACCESS_BACKGROUND_LOCATION": 8,
    # Phone and identity
    "android.permission.READ_PHONE_STATE": 5,
    "android.permission.READ_PHONE_NUMBERS": 6,
    "android.permission.CALL_PHONE": 7,
    "android.permission.PROCESS_OUTGOING_CALLS": 7,
    # Storage
    "android.permission.READ_EXTERNAL_STORAGE": 4,
    "android.permission.WRITE_EXTERNAL_STORAGE": 5,
    "android.permission.MANAGE_EXTERNAL_STORAGE": 7,
    # Malware indicators
    "android.permission.RECEIVE_BOOT_COMPLETED": 5,
    "android.permission.SYSTEM_ALERT_WINDOW": 8,
    "android.permission.BIND_ACCESSIBILITY_SERVICE": 10,
    "android.permission.BIND_DEVICE_ADMIN": 10,
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": 7,
    "android.permission.REQUEST_INSTALL_PACKAGES": 8,
    "android.permission.INSTALL_PACKAGES": 10,
    "android.permission.DELETE_PACKAGES": 7,
    "android.permission.READ_LOGS": 6,
    "android.permission.DISABLE_KEYGUARD": 6,
    "android.permission.WRITE_SETTINGS": 5,
    "android.permission.WRITE_SECURE_SETTINGS": 9,
    "android.permission.PACKAGE_USAGE_STATS": 5,
}

# YARA severity to score mapping
YARA_SEVERITY_SCORES = {
    "critical": 15,
    "high": 10,
    "medium": 6,
    "low": 3,
    "info": 1,
}

# High-risk API call patterns and their individual risk contribution
HIGH_RISK_API_SCORES = {
    "Runtime;->exec": 10,
    "ProcessBuilder;->start": 10,
    "DexClassLoader": 9,
    "InMemoryDexClassLoader": 10,
    "PathClassLoader": 5,
    "Method;->invoke": 6,
    "SmsManager;->sendTextMessage": 9,
    "SmsManager;->sendMultipartTextMessage": 9,
    "DevicePolicyManager": 8,
    "DeviceAdminReceiver": 8,
    "AccessibilityService": 9,
    "Camera;->open": 5,
    "MediaRecorder;->start": 6,
    "WebView;->addJavascriptInterface": 7,
    "WebView;->loadUrl": 4,
    "ClipboardManager;->getPrimaryClip": 5,
    "AccountManager;->getAccounts": 5,
    "PackageManager;->getInstalledPackages": 5,
}


def compute_static_risk(analysis_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compute comprehensive static risk score with detailed breakdown.

    Args:
        analysis_results: Combined results from all static analysis modules.

    Returns:
        Dict with total score, category scores, and detailed breakdown.
    """
    breakdown = {
        "total_score": 0,
        "category_scores": {},
        "details": {},
        "risk_level": "low",
    }

    # 1. Permission risk
    perm_score, perm_details = _score_permissions(analysis_results)
    breakdown["category_scores"]["permissions"] = perm_score
    breakdown["details"]["permissions"] = perm_details

    # 2. IOC risk
    ioc_score, ioc_details = _score_iocs(analysis_results)
    breakdown["category_scores"]["iocs"] = ioc_score
    breakdown["details"]["iocs"] = ioc_details

    # 3. YARA match risk
    yara_score, yara_details = _score_yara(analysis_results)
    breakdown["category_scores"]["yara"] = yara_score
    breakdown["details"]["yara"] = yara_details

    # 4. API call risk
    api_score, api_details = _score_api_calls(analysis_results)
    breakdown["category_scores"]["api_calls"] = api_score
    breakdown["details"]["api_calls"] = api_details

    # 5. Manifest misconfiguration risk
    misconfig_score, misconfig_details = _score_misconfigurations(analysis_results)
    breakdown["category_scores"]["manifest_misconfig"] = misconfig_score
    breakdown["details"]["manifest_misconfig"] = misconfig_details

    # Total
    total = sum(breakdown["category_scores"].values())
    breakdown["total_score"] = min(total, 100)

    # Risk level classification
    breakdown["risk_level"] = _classify_risk(breakdown["total_score"])

    logger.info(
        f"Static risk score: {breakdown['total_score']}/100 "
        f"(level: {breakdown['risk_level']})"
    )

    return breakdown


def _score_permissions(results: Dict[str, Any]) -> Tuple[int, Dict]:
    """Score based on permission profile."""
    max_score = CATEGORY_WEIGHTS["permissions"]
    raw_score = 0
    scored_perms = []

    # Get permissions from various possible structures
    perms = results.get("permissions", {})
    if isinstance(perms, dict):
        all_perms = perms.get("all", perms.get("dangerous", []))
        dangerous = perms.get("dangerous", [])
        indicators = perms.get("malware_indicators", [])
    elif isinstance(perms, list):
        all_perms = perms
        dangerous = []
        indicators = []
    else:
        all_perms = []
        dangerous = []
        indicators = []

    combined = set(all_perms) | set(dangerous) | set(indicators)

    for perm in combined:
        perm_risk = PERMISSION_RISK_SCORES.get(perm, 0)
        if perm_risk > 0:
            raw_score += perm_risk
            scored_perms.append({"permission": perm, "risk_points": perm_risk})

    # Normalize to max_score
    normalized = min(raw_score, max_score * 3)  # Allow raw to go up to 3x before capping
    score = min(int(normalized * max_score / (max_score * 3) * 1.5), max_score)

    return score, {
        "raw_score": raw_score,
        "normalized_score": score,
        "max_score": max_score,
        "permissions_scored": sorted(scored_perms, key=lambda x: x["risk_points"], reverse=True),
    }


def _score_iocs(results: Dict[str, Any]) -> Tuple[int, Dict]:
    """Score based on extracted IOCs."""
    max_score = CATEGORY_WEIGHTS["iocs"]
    raw_score = 0
    details = {}

    iocs = results.get("iocs", {})

    # Raw IPs (non-private) are highly suspicious
    ips = iocs.get("ips", [])
    ip_count = len(ips)
    if ip_count > 0:
        raw_score += min(ip_count * 4, 10)
        details["suspicious_ips"] = ip_count

    # External URLs
    urls = iocs.get("urls", [])
    url_count = len(urls)
    if url_count > 0:
        raw_score += min(url_count * 2, 8)
        details["external_urls"] = url_count

    # Crypto wallets — very suspicious
    wallets = iocs.get("crypto_wallets", [])
    if wallets:
        raw_score += min(len(wallets) * 8, 15)
        details["crypto_wallets"] = len(wallets)

    # Hardcoded API keys / secrets
    keys = iocs.get("api_keys", [])
    if keys:
        raw_score += min(len(keys) * 5, 10)
        details["hardcoded_secrets"] = len(keys)

    # Base64 encoded URLs
    b64_urls = iocs.get("base64_urls", [])
    if b64_urls:
        raw_score += min(len(b64_urls) * 5, 10)
        details["base64_encoded_urls"] = len(b64_urls)

    # Domains
    domains = iocs.get("domains", [])
    if domains:
        raw_score += min(len(domains) * 1, 5)
        details["suspicious_domains"] = len(domains)

    # Emails
    emails = iocs.get("emails", [])
    if emails:
        raw_score += min(len(emails) * 2, 4)
        details["embedded_emails"] = len(emails)
        
    # Financial indicators — highly suspicious if present
    upi_ids = iocs.get("upi_ids", [])
    if upi_ids:
        raw_score += min(len(upi_ids) * 10, 20)
        details["upi_ids"] = len(upi_ids)
        
    ifsc_bank_pairs = iocs.get("ifsc_bank_pairs", [])
    if ifsc_bank_pairs:
        raw_score += min(len(ifsc_bank_pairs) * 15, 30)
        details["ifsc_bank_pairs"] = len(ifsc_bank_pairs)

    score = min(raw_score, max_score)

    return score, {
        "raw_score": raw_score,
        "normalized_score": score,
        "max_score": max_score,
        **details,
    }


def _score_yara(results: Dict[str, Any]) -> Tuple[int, Dict]:
    """Score based on YARA rule matches."""
    max_score = CATEGORY_WEIGHTS["yara"]
    raw_score = 0
    rule_scores = []

    yara_results = results.get("yara_results", {})
    matches = yara_results.get("matches", [])

    # Also support flat list of match names
    if isinstance(matches, list) and all(isinstance(m, str) for m in matches):
        # Legacy format — list of rule names
        raw_score = len(matches) * 8
        rule_scores = [{"rule": m, "severity": "medium", "score": 8} for m in matches]
    else:
        for match in matches:
            severity = match.get("meta", {}).get("severity", "medium").lower()
            match_score = YARA_SEVERITY_SCORES.get(severity, 5)
            raw_score += match_score
            rule_scores.append({
                "rule": match.get("rule", "unknown"),
                "severity": severity,
                "score": match_score,
            })

    score = min(raw_score, max_score)

    return score, {
        "raw_score": raw_score,
        "normalized_score": score,
        "max_score": max_score,
        "rules_triggered": sorted(rule_scores, key=lambda x: x["score"], reverse=True),
        "total_rule_matches": len(rule_scores),
    }


def _score_api_calls(results: Dict[str, Any]) -> Tuple[int, Dict]:
    """Score based on high-risk API call usage."""
    max_score = CATEGORY_WEIGHTS["api_calls"]
    raw_score = 0
    scored_apis = []

    api_calls = results.get("api_calls", {})
    high_risk = api_calls.get("high_risk", [])

    if isinstance(high_risk, list):
        for call in high_risk:
            api_name = call.get("api", "") if isinstance(call, dict) else str(call)
            for pattern, pattern_score in HIGH_RISK_API_SCORES.items():
                if pattern in api_name:
                    raw_score += pattern_score
                    scored_apis.append({
                        "api": api_name[:100],
                        "pattern": pattern,
                        "score": pattern_score,
                    })
                    break

    score = min(raw_score, max_score)

    return score, {
        "raw_score": raw_score,
        "normalized_score": score,
        "max_score": max_score,
        "high_risk_apis": sorted(scored_apis, key=lambda x: x["score"], reverse=True)[:20],
    }


def _score_misconfigurations(results: Dict[str, Any]) -> Tuple[int, Dict]:
    """Score based on manifest security misconfigurations."""
    max_score = CATEGORY_WEIGHTS["manifest_misconfig"]
    raw_score = 0
    scored_issues = []

    severity_scores = {"critical": 8, "high": 5, "medium": 3, "low": 1}

    # From manifest parser output
    misconfigs = results.get("misconfigurations", [])
    for issue in misconfigs:
        severity = issue.get("severity", "medium")
        issue_score = severity_scores.get(severity, 3)
        raw_score += issue_score
        scored_issues.append({
            "issue": issue.get("issue", "unknown"),
            "severity": severity,
            "score": issue_score,
        })

    # From security flags
    flags = results.get("security_flags", {})
    if flags.get("debuggable") is True:
        raw_score += 6
        scored_issues.append({"issue": "debuggable", "severity": "critical", "score": 6})
    if flags.get("allow_backup") is True:
        raw_score += 3
        scored_issues.append({"issue": "allow_backup", "severity": "high", "score": 3})
    if flags.get("uses_cleartext_traffic") is True:
        raw_score += 4
        scored_issues.append({"issue": "cleartext_traffic", "severity": "high", "score": 4})
        
    # From remote access detector
    remote_access = results.get("remote_access_abuse", {})
    if remote_access.get("flagged") is True:
        raw_score += 15
        scored_issues.append({
            "issue": f"remote_access_abuse_{remote_access.get('bundled_sdk', 'unknown')}", 
            "severity": "critical", 
            "score": 15
        })

    score = min(raw_score, max_score)

    return score, {
        "raw_score": raw_score,
        "normalized_score": score,
        "max_score": max_score,
        "issues": sorted(scored_issues, key=lambda x: x["score"], reverse=True),
    }


def _classify_risk(score: int) -> str:
    """Classify risk level based on total score."""
    if score >= 75:
        return "critical"
    elif score >= 50:
        return "high"
    elif score >= 30:
        return "medium"
    elif score >= 10:
        return "low"
    else:
        return "clean"
