"""
Cross-case correlation — finds other cases that share infrastructure (domains,
IPs, BaaS project IDs) or an identical APK fingerprint with the current case.

Works against the application database by default (no external service). If a
Neo4j graph is configured and reachable, it is used for richer graph queries;
otherwise the SQL path produces the same correlation shape.
"""

import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

# Cypher used only when a Neo4j driver is available
_CYPHER = """
MATCH (c:Case {case_id: $case_id})-[:CONTACTS|USES]->(n)<-[:CONTACTS|USES]-(other:Case)
WHERE other.case_id <> $case_id
RETURN other.case_id AS related_case, labels(n)[0] AS shared_type,
       n.value AS shared_value, other.package AS related_package
"""


def _get_driver():
    """Return a Neo4j driver if configured and reachable, else None."""
    try:
        from neo4j import GraphDatabase
        from app.config import settings
        uri = getattr(settings, "NEO4J_URI", None)
        if not uri:
            return None
        driver = GraphDatabase.driver(
            uri, auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD)
        )
        driver.verify_connectivity()
        return driver
    except Exception as e:
        logger.debug(f"Neo4j unavailable, using SQL correlation: {e}")
        return None


def _shape(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Group flat (related_case, shared_type, shared_value, related_package) rows."""
    by_case: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        cid = r.get("related_case")
        if not cid:
            continue
        entry = by_case.setdefault(cid, {
            "case_id": cid,
            "related_package": r.get("related_package"),
            "shared_nodes": [],
        })
        if r.get("related_package") and not entry["related_package"]:
            entry["related_package"] = r["related_package"]
        entry["shared_nodes"].append({
            "type": r.get("shared_type"),
            "value": r.get("shared_value"),
        })
    correlations = list(by_case.values())
    return {
        "status": "success",
        "total_correlated_cases": len(correlations),
        "correlations": correlations,
    }


def _correlate_via_sql(case_id: str, apk_hash: str) -> Dict[str, Any]:
    """Correlate using PhaseResult IOCs + ApkFingerprint stored in the app DB."""
    from app.models.session import SessionLocal
    from app.models.database import Case, PhaseResult

    db = SessionLocal()
    rows: List[Dict[str, Any]] = []
    try:
        def iocs_of(result: dict) -> Dict[str, set]:
            steps = (result or {}).get("steps", {})
            ioc = steps.get("iocs", {}).get("data", {}) if steps else {}
            out = {
                "Domain": set(d.lower() for d in ioc.get("domains", []) or []),
                "IPAddress": set(ioc.get("ips", []) or []),
            }
            baas = steps.get("baas_detection", {}).get("data", {}) if steps else {}
            out["BaaSProject"] = {p for p in (baas.get("project_ids", []) or []) if p}
            return out

        # Current case IOCs
        mine_phase = db.query(PhaseResult).filter(
            PhaseResult.case_id == case_id, PhaseResult.phase == "static"
        ).first()
        mine = iocs_of(mine_phase.result) if mine_phase else {"Domain": set(), "IPAddress": set(), "BaaSProject": set()}

        # Compare against every other case's static IOCs and fingerprint
        others = db.query(PhaseResult).filter(
            PhaseResult.phase == "static", PhaseResult.case_id != case_id
        ).all()
        pkg_by_case = {str(c.id): c.package_name for c in db.query(Case).all()}

        for pr in others:
            their = iocs_of(pr.result)
            ocid = str(pr.case_id)
            for node_type, values in mine.items():
                for shared in values & their.get(node_type, set()):
                    rows.append({
                        "related_case": ocid, "shared_type": node_type,
                        "shared_value": shared, "related_package": pkg_by_case.get(ocid),
                    })

        # Identical APK (same hash = same sample seen in another case)
        if apk_hash:
            for c in db.query(Case).filter(Case.apk_hash == apk_hash, Case.id != case_id).all():
                rows.append({
                    "related_case": str(c.id), "shared_type": "APK",
                    "shared_value": apk_hash, "related_package": c.package_name,
                })
    finally:
        db.close()
    return _shape(rows)


def find_correlated_cases(case_id: str, apk_hash: str = "") -> Dict[str, Any]:
    """Find cases correlated with `case_id`. Uses Neo4j if available, else SQL."""
    driver = _get_driver()
    if driver is not None:
        try:
            with driver.session() as session:
                result = session.run(_CYPHER, case_id=case_id)
                rows = [dict(r) for r in result]
            return _shape(rows)
        except Exception as e:
            logger.warning(f"Neo4j correlation failed ({e}); falling back to SQL")
        finally:
            try:
                driver.close()
            except Exception:
                pass

    try:
        return _correlate_via_sql(case_id, apk_hash)
    except Exception as e:
        logger.error(f"Correlation failed: {e}")
        return {"status": "failed", "total_correlated_cases": 0, "correlations": [], "errors": [str(e)]}
