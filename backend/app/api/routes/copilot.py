"""
Co-Pilot REST API — Local Ollama-Only Chat Endpoint
Loads REAL case analysis data from the database and feeds it to the local LLM.
All inference is routed through the local Ollama instance — zero external API calls.
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from uuid import UUID
import json
import logging

from sqlalchemy.orm import Session
from app.api.dependencies import get_db
from app.models.database import Case, PhaseResult
from app.engines.intelligence import llm_client

router = APIRouter()
logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are APEX-X Co-Pilot, an expert Android malware forensics AI assistant embedded in the APEX-X threat intelligence platform.

You receive the COMPLETE analysis data for the currently selected APK case. This data was extracted by the APEX-X analysis engines: APKTool, JADX, Androguard, Manifest Parser, YARA Scanner, IOC Extractor, Dynamic Monkey Runner, and C2 Intelligence Correlator.

HOW TO RESPOND:
- Reference SPECIFIC data from the context (exact permission names, exact domain names, exact CWE IDs, exact CVSS scores)
- When asked about permissions, list the actual permission names and their risk levels from the data
- When asked about IOCs, cite the exact URLs/domains/IPs from the data
- When asked about vulnerabilities, reference the specific title, CVSS score, CWE ID, and OWASP category
- Calculate and cite statistics from the data (e.g., "3 out of 8 permissions are dangerous")
- For risk assessment, explain WHY the threat_score is what it is, based on the specific findings
- Use forensic/security professional language
- Use bullet points and structured formatting for clarity
- Be thorough but concise
- NEVER fabricate or hallucinate data. Only reference what exists in the provided context.
- If asked about something not in the context (e.g., dynamic analysis when only static was run), clearly state that data is not available."""


class Message(BaseModel):
    role: str
    content: str


class CopilotRequest(BaseModel):
    message: str
    case_id: Optional[str] = None
    context: Optional[Dict[str, Any]] = None
    history: Optional[List[Message]] = []


def _safe_slice(obj, limit):
    if isinstance(obj, list):
        return obj[:limit]
    return obj

def _load_case_context(case_id: str, db: Session) -> Dict[str, Any]:
    """Load real analysis data from the database for a given case."""
    try:
        case_uuid = UUID(case_id)
    except ValueError:
        return {"error": "Invalid case ID"}

    case = db.query(Case).filter(Case.id == case_uuid).first()
    if not case:
        return {"error": "Case not found"}

    context = {
        "case_number": f"CASE-{str(case.id)[:8].upper()}",
        "apk_name": case.apk_name,
        "sha256": case.apk_hash,
        "status": case.status,
        "created_at": str(case.created_at) if case.created_at else None,
    }

    # Load all phase results
    phase_results = db.query(PhaseResult).filter(PhaseResult.case_id == case_uuid).all()
    
    for pr in phase_results:
        if pr.phase == "static" and pr.result:
            result = pr.result
            steps = result.get("steps", {})
            
            # Extract manifest data
            manifest = steps.get("manifest", {}).get("data", {})
            if "package_name" in manifest:
                context["package_name"] = manifest["package_name"]
            
            context["security_flags"] = manifest.get("security_flags", {})
            context["misconfigurations"] = manifest.get("misconfigurations", [])
            context["activities"] = _safe_slice(manifest.get("activities"), 10)
            context["services"] = _safe_slice(manifest.get("services"), 10)
            context["receivers"] = _safe_slice(manifest.get("receivers"), 10)
            
            # Extract permissions
            androguard = steps.get("androguard", {}).get("data", {})
            permissions = androguard.get("permissions", {})
            context["permissions"] = {
                "all": permissions.get("all", []),
                "dangerous": permissions.get("dangerous", []),
                "total": len(permissions.get("all", [])),
                "dangerous_count": len(permissions.get("dangerous", [])),
            }
            
            # Extract API calls
            api_calls = androguard.get("api_calls", {})
            context["high_risk_apis"] = _safe_slice(api_calls.get("high_risk"), 15)
            
            # Extract IOCs
            iocs = steps.get("iocs", {}).get("data", {})
            context["iocs"] = {
                "urls": _safe_slice(iocs.get("urls"), 20),
                "domains": _safe_slice(iocs.get("domains"), 20),
                "ips": _safe_slice(iocs.get("ips"), 10),
                "emails": _safe_slice(iocs.get("emails"), 10),
                "api_keys": _safe_slice(iocs.get("api_keys"), 5),
            }
            
            # YARA matches
            yara = steps.get("yara", {}).get("data", {})
            context["yara_matches"] = yara.get("matches", [])
            
            context["static_risk_score"] = result.get("risk_score", 0)
            context["static_threat_score"] = result.get("threat_score", 0)
            
        elif pr.phase == "dynamic" and pr.result:
            result = pr.result
            context["dynamic_analysis"] = {
                "status": result.get("status"),
                "mode": result.get("mode"),  # emulator = real execution, heuristic = code scan only
                "duration_seconds": result.get("duration_seconds"),
                "events": [
                    {k: e.get(k) for k in ("api_call", "category", "risk_level", "description", "source")}
                    for e in _safe_slice(result.get("events") or [], 60)
                ],
                "network_activity": [
                    {k: n.get(k) for k in ("destination", "ip", "port", "protocol", "bytes_sent", "bytes_received", "static_reference")}
                    for n in _safe_slice(result.get("network_activity") or [], 30)
                ],
                "dns_queries": _safe_slice(result.get("dns_queries"), 30),
                "dropped_packages": result.get("dropped_packages", []),
                "running_services": result.get("running_services", []),
                "app_crashed": result.get("app_crashed"),
                "behaviors": result.get("behaviors", {}),
                "risk_score": result.get("risk_score", 0),
                "errors": result.get("errors", []),
            }
            
        elif pr.phase == "c2_intelligence" and pr.result:
            result = pr.result
            context["c2_intelligence"] = {
                "risk_score": result.get("risk_score", 0),
                "contacted_infrastructure": _safe_slice(result.get("contacted_infrastructure"), 10),
                "attribution": result.get("attribution", {}),
                "threat_indicators": _safe_slice(result.get("threat_indicators"), 10),
            }
            
        elif pr.phase == "vulnerability" and pr.result:
            result = pr.result
            findings = result.get("findings", [])
            context["vulnerabilities"] = [{
                "title": f.get("title", f.get("name", "")),
                "severity": f.get("severity", ""),
                "cvss_score": f.get("cvss_score", 0),
                "cwe_id": f.get("cwe_id", ""),
                "owasp_category": f.get("owasp_category", ""),
                "description": f.get("description", ""),
            } for f in findings]
            context["vuln_risk_score"] = result.get("risk_score", 0)

    return context


@router.post("")
async def copilot_chat(request: CopilotRequest, db: Session = Depends(get_db)):
    """
    REST endpoint for Co-Pilot chat.
    Routes all inference to the LOCAL Ollama instance — no external APIs.
    """
    if not request.message:
        raise HTTPException(status_code=400, detail="No message provided")

    # Check local LLM health
    health = llm_client.check_health()
    if health.get("status") != "healthy":
        raise HTTPException(
            status_code=503,
            detail="Local LLM (Ollama) is not available. Start it with: ollama serve"
        )

    # Build context — prefer DB-loaded real data over frontend-provided mock data
    prompt_parts = []

    if request.case_id:
        db_context = _load_case_context(request.case_id, db)
        if "error" not in db_context:
            prompt_parts.append(
                f"CASE ANALYSIS DATA (from APEX-X database):\n{json.dumps(db_context, indent=2, default=str)}"
            )
        elif request.context:
            # Fall back to frontend-provided context for mock cases
            prompt_parts.append(
                f"CURRENT CASE CONTEXT:\n{json.dumps(request.context, indent=2)}"
            )
    elif request.context:
        prompt_parts.append(
            f"CURRENT CASE CONTEXT:\n{json.dumps(request.context, indent=2)}"
        )

    # Add conversation history
    if request.history:
        for msg in request.history:
            if msg.role == "user":
                prompt_parts.append(f"User: {msg.content}")
            elif msg.role in ("assistant", "ai"):
                prompt_parts.append(f"Assistant: {msg.content}")

    prompt_parts.append(f"User: {request.message}")
    prompt_parts.append("Assistant:")

    full_prompt = "\n\n".join(prompt_parts)

    try:
        logger.info(f"Co-Pilot REST request: prompt_len={len(full_prompt)}")
        response_text = llm_client.generate(
            prompt=full_prompt,
            model=llm_client.MODEL_CODER,
            system=SYSTEM_PROMPT,
            temperature=0.3,
            max_tokens=2048,
        )

        if response_text.startswith("[ERROR"):
            raise HTTPException(
                status_code=503,
                detail=f"LLM inference error: {response_text}"
            )

        return {"message": response_text.strip()}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Co-Pilot error: {e}")
        raise HTTPException(status_code=502, detail=f"AI service error: {str(e)}")
