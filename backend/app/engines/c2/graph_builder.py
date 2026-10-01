"""
C2 Graph Builder — Threat Infrastructure Visualization
Constructs interactive network graphs from analysis data showing
APK → Domain/IP/URL communication paths for C2 attribution.
"""

import json
import os
import logging
from typing import Dict, Any, List

from app.engines import virustotal_client
from app.engines import ipinfo_client

logger = logging.getLogger(__name__)


def build_c2_graph(
    case_dir: str,
    apk_hash: str,
    package_name: str = "unknown",
) -> Dict[str, Any]:
    """
    Build a frontend-compatible graph (nodes + edges) for the C2 tab.
    Sources: static IOCs + dynamic report + deep scan intelligence.
    """
    nodes = []
    edges = []
    node_ids = set()
    edge_counter = [0]

    def add_edge(source, target, label, etype="communication"):
        edge_counter[0] += 1
        edges.append({
            "id": f"e{edge_counter[0]}",
            "source": source,
            "target": target,
            "label": label,
            "type": etype,
        })

    # ── Central APK node ──
    apk_id = f"apk-{package_name}"
    nodes.append({
        "id": apk_id,
        "label": package_name,
        "type": "apk",
        "risk": "high",
        "metadata": {"hash": apk_hash},
    })
    node_ids.add(apk_id)

    # ── Collect IOCs from local analysis ──
    domains = set()
    ips = set()
    urls = set()

    # From static IOC list
    ioc_path = os.path.join(case_dir, "static_analysis", "ioc_list.json")
    if os.path.exists(ioc_path):
        try:
            with open(ioc_path, "r") as f:
                iocs = json.load(f)
            domains.update(iocs.get("domains", []))
            ips.update(iocs.get("ips", []))
            urls.update(iocs.get("urls", []))
        except Exception as e:
            logger.debug(f"Could not read IOC list: {e}")

    # From dynamic report (network_activity)
    dynamic_path = os.path.join(case_dir, "dynamic_analysis", "dynamic_report.json")
    if os.path.exists(dynamic_path):
        try:
            with open(dynamic_path, "r") as f:
                dyn = json.load(f)
            for net in dyn.get("network_activity", []):
                dest = net.get("destination", "")
                ip = net.get("ip", "")
                if dest:
                    domains.add(dest)
                if ip:
                    ips.add(ip)
        except Exception as e:
            logger.debug(f"Could not read dynamic report: {e}")

    # From pentest report (pentest_analysis/pentest_report.json)
    pentest_path = os.path.join(case_dir, "pentest_analysis", "pentest_report.json")
    if os.path.exists(pentest_path):
        try:
            with open(pentest_path, "r") as f:
                pen = json.load(f)
            # Extract from events with category "network"
            for ev in pen.get("events", []):
                if isinstance(ev, dict) and ev.get("category") == "network":
                    desc = ev.get("description", "")
                    api_call = ev.get("api_call", "")
                    # Extract IP from description like "App connected to X.X.X.X (X.X.X.X) on port 443/TCP"
                    _extract_network_iocs(desc, ips, domains)
                    _extract_network_iocs(api_call, ips, domains)
        except Exception as e:
            logger.debug(f"Could not read pentest report: {e}")

    # From DB dynamic phase results (fallback when data is only in DB)
    try:
        from app.models.session import SessionLocal
        from app.models.database import PhaseResult
        import re as _re
        case_uuid = _normalize_case_id(case_dir)
        if case_uuid:
            _db = SessionLocal()
            try:
                dyn_phase = _db.query(PhaseResult).filter(
                    PhaseResult.case_id == case_uuid,
                    PhaseResult.phase == "dynamic"
                ).first()
                if dyn_phase and dyn_phase.result:
                    dyn_data = dyn_phase.result if isinstance(dyn_phase.result, dict) else json.loads(dyn_phase.result)
                    for ev in dyn_data.get("events", []):
                        if isinstance(ev, dict) and ev.get("category") == "network":
                            _extract_network_iocs(ev.get("description", ""), ips, domains)
                            _extract_network_iocs(ev.get("api_call", ""), ips, domains)
                    # Also check pentest_data.network_activity
                    pd = dyn_data.get("pentest_data", {})
                    for na in pd.get("network_activity", []):
                        if isinstance(na, dict):
                            if na.get("ip"):
                                ips.add(na["ip"])
                            if na.get("destination"):
                                domains.add(na["destination"])
            finally:
                _db.close()
    except Exception as e:
        logger.debug(f"Could not read dynamic DB results: {e}")
    contacted_ips_data = []
    contacted_domains_data = []
    contacted_urls_data = []
    dropped_files_data = []
    detection_summary = {}

    if virustotal_client._has_key():
        try:
            file_hash = virustotal_client.sha256_of_file(
                _find_apk_path(case_dir)
            ) if _find_apk_path(case_dir) else apk_hash

            report = virustotal_client.get_file_report(file_hash)
            if report:
                detection_summary = virustotal_client.extract_detection_summary(report)

            contacted_ips_data = virustotal_client.get_contacted_ips(file_hash)
            contacted_domains_data = virustotal_client.get_contacted_domains(file_hash)
            contacted_urls_data = virustotal_client.get_contacted_urls(file_hash)
            dropped_files_data = virustotal_client.get_dropped_files(file_hash)

            # Add deep scan data to our IOC sets
            for ip_obj in contacted_ips_data:
                ip_addr = ip_obj.get("id", "")
                if ip_addr:
                    ips.add(ip_addr)

            for dom_obj in contacted_domains_data:
                dom_name = dom_obj.get("id", "")
                if dom_name:
                    domains.add(dom_name)

            for url_obj in contacted_urls_data:
                ctx = url_obj.get("context_attributes", {})
                url_val = ctx.get("url", url_obj.get("id", ""))
                if url_val:
                    urls.add(url_val)

        except Exception as e:
            logger.debug(f"Deep scan intelligence enrichment error: {e}")

    # ── Build graph nodes and edges ──

    # Filter out noise domains (Google Play, system services)
    noise_patterns = [
        "googleapis.com", "google.com", "gstatic.com", "android.com",
        "play.google", "1e100.net", "googleusercontent.com",
        "crashlytics", "firebase", "gvt1.com", "gvt2.com",
    ]

    def is_noise(name: str) -> bool:
        return any(p in name.lower() for p in noise_patterns)

    # Domain nodes
    for domain in sorted(domains):
        if is_noise(domain):
            continue
        did = f"domain-{domain}"
        if did not in node_ids:
            # Check if domain is in contacted_domains_data for risk
            risk = "medium"
            country = ""
            for dd in contacted_domains_data:
                if dd.get("id") == domain:
                    attrs = dd.get("attributes", {})
                    mal = attrs.get("last_analysis_stats", {}).get("malicious", 0)
                    if mal > 5:
                        risk = "critical"
                    elif mal > 0:
                        risk = "high"
                    country = attrs.get("country", "")
                    break

            nodes.append({
                "id": did,
                "label": domain,
                "type": "domain",
                "risk": risk,
                "metadata": {"country": country},
            })
            node_ids.add(did)
            add_edge(apk_id, did, "CONTACTS")

    # IP nodes — enriched with ipinfo geolocation
    for ip in sorted(ips):
        if ip.startswith("10.") or ip.startswith("127.") or ip.startswith("192.168."):
            continue
        iid = f"ip-{ip}"
        if iid not in node_ids:
            risk = "medium"
            country = ""
            asn_owner = ""
            city = ""
            lat = 0.0
            lng = 0.0
            classification = "unknown"

            # Try VirusTotal data first for maliciousness
            for ip_obj in contacted_ips_data:
                if ip_obj.get("id") == ip:
                    attrs = ip_obj.get("attributes", {})
                    mal = attrs.get("last_analysis_stats", {}).get("malicious", 0)
                    if mal > 5:
                        risk = "critical"
                    elif mal > 0:
                        risk = "high"
                    country = attrs.get("country", "")
                    asn_owner = attrs.get("as_owner", "")
                    break

            # Enrich with ipinfo for geolocation, ISP, and classification
            try:
                geo = ipinfo_client.enrich_ip(ip)
                if geo.get("country"):
                    country = geo["country"]
                if geo.get("city"):
                    city = geo["city"]
                if geo.get("org"):
                    asn_owner = geo["org"]
                lat = geo.get("lat", 0.0)
                lng = geo.get("lng", 0.0)
                classification = geo.get("classification", "unknown")

                # Upgrade risk if VT didn't flag it but ipinfo says suspicious
                if risk == "medium" and classification == "suspicious":
                    risk = "high"
            except Exception as e:
                logger.debug(f"IPInfo enrichment failed for {ip}: {e}")

            nodes.append({
                "id": iid,
                "label": ip,
                "type": "ip",
                "risk": risk,
                "metadata": {
                    "country": country,
                    "city": city,
                    "asn": asn_owner,
                    "lat": lat,
                    "lng": lng,
                    "classification": classification,
                },
            })
            node_ids.add(iid)
            add_edge(apk_id, iid, "CONNECTS_TO")

    # Domain → IP resolution edges (from contacted data)
    for dom_obj in contacted_domains_data:
        dom_name = dom_obj.get("id", "")
        did = f"domain-{dom_name}"
        if did not in node_ids:
            continue
        # Try to find resolved IPs
        attrs = dom_obj.get("attributes", {})
        last_dns = attrs.get("last_dns_records", [])
        for record in last_dns:
            if record.get("type") in ("A", "AAAA"):
                resolved_ip = record.get("value", "")
                iid = f"ip-{resolved_ip}"
                if iid in node_ids:
                    add_edge(did, iid, "RESOLVES_TO", "dns")

    # URL nodes (limit to suspicious ones)
    url_count = 0
    for url in sorted(urls):
        if url_count >= 10:
            break
        if is_noise(url):
            continue
        uid = f"url-{hash(url) & 0xFFFF}"
        if uid not in node_ids:
            # Truncate for display
            label = url if len(url) < 50 else url[:47] + "..."
            nodes.append({
                "id": uid,
                "label": label,
                "type": "url",
                "risk": "high",
                "metadata": {"full_url": url},
            })
            node_ids.add(uid)
            add_edge(apk_id, uid, "REQUESTS", "http")
            url_count += 1

    # Dropped file nodes
    for df in dropped_files_data[:5]:
        df_hash = df.get("id", "")[:12]
        df_attrs = df.get("attributes", {})
        df_name = df_attrs.get("meaningful_name", df_attrs.get("type_description", df_hash))
        dfid = f"dropped-{df_hash}"
        if dfid not in node_ids:
            nodes.append({
                "id": dfid,
                "label": df_name if len(df_name) < 30 else df_name[:27] + "...",
                "type": "file",
                "risk": "critical",
                "metadata": {"sha256": df.get("id", "")},
            })
            node_ids.add(dfid)
            add_edge(apk_id, dfid, "DROPS", "payload")

    return {
        "status": "success",
        "nodes": nodes,
        "edges": edges,
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "domains": sorted(domains - {d for d in domains if is_noise(d)}),
        "ips": sorted(ips - {ip for ip in ips if ip.startswith(("10.", "127.", "192.168."))}),
        "urls": sorted(urls),
        "detection_summary": detection_summary,
        "dropped_files_count": len(dropped_files_data),
    }


def _find_apk_path(case_dir: str) -> str:
    """Find the APK file in the case directory."""
    for f in os.listdir(case_dir):
        if f.endswith(".apk"):
            return os.path.join(case_dir, f)
    return ""


def _extract_network_iocs(text: str, ips: set, domains: set):
    """Extract IPs and domain names from a description string."""
    import re
    # Match IPv4 addresses
    ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
    for match in ip_pattern.finditer(text):
        ip = match.group(1)
        # Validate IP octets
        parts = ip.split('.')
        if all(0 <= int(p) <= 255 for p in parts):
            ips.add(ip)

    # Match domain names (e.g., sn-in-f119.1e100.net, example.com)
    domain_pattern = re.compile(r'\b([a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})\b')
    for match in domain_pattern.finditer(text):
        domain = match.group(1)
        # Skip if it looks like an IP or version string
        if not re.match(r'^\d+\.\d+\.\d+\.\d+$', domain) and len(domain) > 4:
            domains.add(domain)


def _normalize_case_id(case_dir: str):
    """Extract a UUID object from the case directory path."""
    import uuid
    basename = os.path.basename(case_dir.rstrip('/\\'))
    try:
        return uuid.UUID(basename)
    except (ValueError, AttributeError):
        return None

