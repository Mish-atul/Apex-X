"""
IPInfo Client — IP Geolocation & Classification
Enriches IP addresses with location, ISP, org data using ipinfo.io Lite API.
Classifies IPs as benign/suspicious/malicious based on ASN ownership.
"""

import logging
import time
from typing import Dict, Any, List

import requests

from app.config import settings

logger = logging.getLogger(__name__)

_BASE = "https://api.ipinfo.io/lite"
_CACHE: Dict[str, Dict[str, Any]] = {}

# Well-known legitimate ASN organizations — traffic to these is almost certainly benign
_BENIGN_ORGS = [
    "google", "amazon", "microsoft", "cloudflare", "akamai", "fastly",
    "apple", "facebook", "meta", "twitter", "mozilla", "github",
    "digitalocean", "linode", "oracle", "ibm", "samsung", "huawei",
    "alibaba", "tencent", "adobe", "spotify", "netflix",
    "whatsapp", "telegram", "signal",
]

# Known bulletproof / shady hosting providers — traffic here is suspicious
_SUSPICIOUS_ORGS = [
    "choopa", "vultr", "hostwinds", "hostinger", "namecheap",
    "frantech", "buyvm", "nocix", "quadranet", "psychz",
    "combahton", "meverywhere", "leaseweb", "ovh", "hetzner"
]

# Fallback coordinates since the Lite API doesn't provide them
_COUNTRY_COORDS = {
    "US": (37.0902, -95.7129),
    "CA": (56.1304, -106.3468),
    "GB": (55.3781, -3.4360),
    "DE": (51.1657, 10.4515),
    "FR": (46.2276, 2.2137),
    "IN": (20.5937, 78.9629),
    "CN": (35.8617, 104.1954),
    "RU": (61.524, 105.3188),
    "BR": (-14.235, -51.9253),
    "AU": (-25.2744, 133.7751),
    "JP": (36.2048, 138.2529),
    "SG": (1.3521, 103.8198),
    "NL": (52.1326, 5.2913),
}

def _get_headers() -> Dict[str, str]:
    return {"Authorization": f"Bearer {settings.IPINFO_API_TOKEN}"}


def _has_token() -> bool:
    return bool(settings.IPINFO_API_TOKEN)


def enrich_ip(ip: str) -> Dict[str, Any]:
    """
    Enrich a single IP with geolocation, ISP info, and classification.
    Returns dict with: ip, city, region, country, loc, org, classification, lat, lng
    """
    # Check cache first
    if ip in _CACHE:
        return _CACHE[ip]

    result = {
        "ip": ip,
        "city": "",
        "region": "",
        "country": "",
        "org": "",
        "lat": 0.0,
        "lng": 0.0,
        "classification": "unknown",
    }

    if not _has_token():
        logger.debug("No IPInfo token configured, skipping enrichment")
        return result

    for attempt in range(3):
        try:
            r = requests.get(
                f"{_BASE}/{ip}",
                headers=_get_headers(),
                timeout=10,
            )
            if r.status_code == 429:
                logger.debug(f"IPInfo rate limited, waiting 2s (attempt {attempt+1})")
                time.sleep(2)
                continue
            if not r.ok:
                logger.debug(f"IPInfo request failed ({r.status_code}) for {ip}")
                break

            data = r.json()
            result["country"] = data.get("country", "")
            
            # Lite API uses as_name instead of org
            result["org"] = data.get("as_name", data.get("org", ""))
            
            # Fallback coords from country_code
            cc = data.get("country_code", "")
            if cc in _COUNTRY_COORDS:
                result["lat"], result["lng"] = _COUNTRY_COORDS[cc]

            # Classify the IP
            result["classification"] = _classify_ip(result["org"])

            # Cache it
            _CACHE[ip] = result
            logger.info(f"IPInfo enriched {ip} → {result['country']} ({result['org']}) [{result['classification']}]")
            return result

        except requests.RequestException as e:
            logger.debug(f"IPInfo request error for {ip}: {e}")
            break

    return result


def enrich_ips(ips: List[str]) -> List[Dict[str, Any]]:
    """Enrich a list of IPs. Skips private/loopback addresses."""
    results = []
    for ip in ips:
        # Skip private/loopback
        if ip.startswith(("10.", "127.", "192.168.", "172.16.", "0.", "255.")):
            continue
        enriched = enrich_ip(ip)
        results.append(enriched)
    return results


def _classify_ip(org: str) -> str:
    """
    Classify an IP based on its ASN organization.
    Returns: 'benign', 'suspicious', or 'unknown'
    """
    if not org:
        return "unknown"

    org_lower = org.lower()

    # Check benign first
    for pattern in _BENIGN_ORGS:
        if pattern in org_lower:
            return "benign"

    # Check known shady hosting
    for pattern in _SUSPICIOUS_ORGS:
        if pattern in org_lower:
            return "suspicious"

    # Generic hosting / VPS providers are suspicious for malware C2
    hosting_keywords = ["hosting", "vps", "server", "dedicated", "colocation", "data center"]
    if any(kw in org_lower for kw in hosting_keywords):
        return "suspicious"

    return "unknown"
