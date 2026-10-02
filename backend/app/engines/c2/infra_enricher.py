"""
Infrastructure enricher — classifies IPs and domains observed in analysis
without requiring any external service. Flags private ranges, known cloud
providers, suspicious TLDs and DGA-like (algorithmically generated) domains.
Optionally augments IP data with the bundled ipinfo client when a token exists.
"""

import re
import math
import ipaddress
from typing import Dict, Any, List

# Minimal well-known cloud ranges (first octet / prefix heuristics). This is a
# lightweight local classifier; ipinfo enrichment refines it when available.
_CLOUD_PREFIXES = {
    "Amazon AWS": ["3.", "13.", "15.", "18.", "34.", "35.", "52.", "54."],
    "Google Cloud": ["34.64.", "35.184.", "35.188.", "104.154.", "104.196.", "130.211."],
    "Microsoft Azure": ["20.", "40.", "51.", "52.136.", "104.40."],
    "DigitalOcean": ["104.131.", "138.197.", "159.65.", "165.227.", "167.71."],
    "Cloudflare": ["104.16.", "104.17.", "104.18.", "172.64.", "173.245."],
}

# TLDs disproportionately abused by malware / phishing campaigns
_SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".club", ".work",
    ".click", ".link", ".pw", ".cc", ".su", ".ru", ".icu", ".rest", ".cyou",
}


def enrich_ip(ip: str) -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "address": ip, "is_private": False, "provider": "Unknown",
        "country": "Unknown", "risk_indicators": [],
    }
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        info["risk_indicators"].append("Not a valid IP address")
        return info

    if addr.is_private or addr.is_loopback or addr.is_link_local:
        info["is_private"] = True
        info["provider"] = "Private Network"
        info["country"] = "Local"
        return info

    for provider, prefixes in _CLOUD_PREFIXES.items():
        if any(ip.startswith(p) for p in prefixes):
            info["provider"] = provider
            info["country"] = "US"
            break

    # Optional live enrichment (geo/ASN) when an ipinfo token is configured
    try:
        from app.engines import ipinfo_client
        # Only consult the live service to fill gaps the local classifier left blank,
        # so classification stays deterministic and offline-safe.
        if (info["country"] == "Unknown" or info["provider"] == "Unknown") \
                and getattr(ipinfo_client, "_has_token", lambda: False)():
            data = ipinfo_client.enrich_ip(ip) or {}
            if info["country"] == "Unknown" and data.get("country"):
                info["country"] = data["country"]
            if info["provider"] == "Unknown" and (data.get("org") or data.get("provider")):
                info["provider"] = data.get("org") or data.get("provider")
            if data.get("hostname"):
                info["hostname"] = data["hostname"]
    except Exception:
        pass

    return info


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in counts.values())


def _looks_like_dga(label: str) -> bool:
    """Heuristic DGA detector: long, high-entropy, low vowel ratio, digit-mixed."""
    core = re.sub(r"[^a-z0-9]", "", label.lower())
    if len(core) < 8:
        return False
    vowels = sum(c in "aeiou" for c in core)
    vowel_ratio = vowels / len(core)
    entropy = _shannon_entropy(core)
    has_digits = any(c.isdigit() for c in core)
    consonant_runs = max((len(m) for m in re.findall(r"[bcdfghjklmnpqrstvwxyz]+", core)), default=0)
    signals = 0
    if entropy >= 3.2:
        signals += 1
    if vowel_ratio < 0.30:
        signals += 1
    if consonant_runs >= 5:
        signals += 1
    if has_digits and len(core) >= 10:
        signals += 1
    return signals >= 2


def enrich_domain(domain: str) -> Dict[str, Any]:
    domain = (domain or "").strip().lower().rstrip(".")
    info: Dict[str, Any] = {
        "domain": domain, "tld": "", "suspicious_tld": False,
        "is_dga": False, "risk_indicators": [],
    }
    if not domain or "." not in domain:
        info["risk_indicators"].append("Malformed domain")
        return info

    tld = "." + domain.rsplit(".", 1)[-1]
    info["tld"] = tld
    if tld in _SUSPICIOUS_TLDS:
        info["suspicious_tld"] = True
        info["risk_indicators"].append(f"Suspicious TLD ({tld}) commonly used by malware")

    labels = domain.split(".")
    sld = labels[-2] if len(labels) >= 2 else labels[0]
    if _looks_like_dga(sld):
        info["is_dga"] = True
        info["risk_indicators"].append("DGA-like domain (algorithmically generated name)")

    if len(domain) > 40:
        info["risk_indicators"].append("Unusually long domain name")

    return info


def enrich_indicators(ips: List[str], domains: List[str]) -> Dict[str, Any]:
    """Convenience wrapper used by the C2 engine to enrich a batch of IOCs."""
    return {
        "ips": [enrich_ip(ip) for ip in dict.fromkeys(ips)],
        "domains": [enrich_domain(d) for d in dict.fromkeys(domains)],
    }
