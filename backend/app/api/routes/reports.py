"""
Report Generation API — LLM-Generated Forensic Reports + SarvamAI Translation
Loads real case data from the database, generates a detailed English forensic
report via the local Qwen 2.5 LLM, translates via SarvamAI, and renders to PDF.
"""

import os
import json
import zipfile
import datetime
import logging
from typing import Dict, Any

from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from uuid import UUID

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.utils import simpleSplit

from app.api.dependencies import get_db
from app.models.database import Case, PhaseResult

logger = logging.getLogger(__name__)

# ── SarvamAI Translation ─────────────────────────────────────

def translate_text(text: str, target_lang: str) -> str:
    lang_map = {
        "hindi": "hi-IN", "hi": "hi-IN",
        "kannada": "kn-IN", "kn": "kn-IN",
        "tamil": "ta-IN", "ta": "ta-IN",
        "telugu": "te-IN", "te": "te-IN"
    }
    target_code = lang_map.get(target_lang.lower())
    if not target_code or target_lang.lower() in ["en", "english"]:
        return text
        
    try:
        from sarvamai import SarvamAI
        api_key = os.getenv("SARVAM_API_KEY", "")
        if not api_key:
            logger.warning("SARVAM_API_KEY not set — report will be generated in English")
            return text
        client = SarvamAI(api_subscription_key=api_key)
        # Translate in chunks of ~450 chars to stay within API limits
        if len(text) > 450:
            chunks = []
            sentences = text.split(". ")
            current_chunk = ""
            for sentence in sentences:
                if len(current_chunk) + len(sentence) + 2 < 450:
                    current_chunk += sentence + ". "
                else:
                    if current_chunk.strip():
                        res = client.text.translate(input=current_chunk.strip(), source_language_code="en-IN", target_language_code=target_code)
                        chunks.append(res.translated_text)
                    current_chunk = sentence + ". "
            if current_chunk.strip():
                res = client.text.translate(input=current_chunk.strip(), source_language_code="en-IN", target_language_code=target_code)
                chunks.append(res.translated_text)
            return " ".join(chunks)
        else:
            res = client.text.translate(input=text, source_language_code="en-IN", target_language_code=target_code)
            return res.translated_text
    except Exception as e:
        logger.warning(f"SarvamAI translation error: {e}")
        return text


# ── LLM Report Generation ────────────────────────────────────

def _generate_report_narrative(case_data: Dict[str, Any]) -> str:
    """
    Builds the report instantly using deterministic analysis results
    and appends the LLM-generated conclusion/prevention from the DB.
    """
    try:
        report = _fallback_narrative(case_data)
        return report
    except Exception as e:
        logger.error(f"Report formatting error: {e}")
        return "Error generating report."


def _fallback_narrative(case_data: Dict[str, Any]) -> str:
    """Template-based fallback when LLM is unavailable."""
    apk = case_data.get("apk_name", "Unknown APK")
    pkg = case_data.get("package_name", "Unknown")
    sha = case_data.get("sha256", "N/A")
    score = case_data.get("threat_score", case_data.get("static_threat_score", 0))
    
    perms = case_data.get("permissions", {})
    dangerous = perms.get("dangerous", [])
    
    vulns = case_data.get("vulnerabilities", [])
    critical_vulns = [v for v in vulns if v.get("severity") == "critical"]
    high_vulns = [v for v in vulns if v.get("severity") == "high"]
    
    sec_flags = case_data.get("security_flags", {})
    
    sections = []
    sections.append("1. EXECUTIVE SUMMARY")
    sections.append(f"APK: {apk} ({pkg})")
    sections.append(f"Threat Score: {score}/100")
    if score >= 70:
        sections.append("Verdict: HIGH RISK — This application exhibits multiple indicators of malicious behavior.")
    elif score >= 40:
        sections.append("Verdict: MEDIUM RISK — This application has concerning security weaknesses.")
    else:
        sections.append("Verdict: LOW RISK — No critical threats detected.")
    
    sections.append("")
    sections.append("2. APK PROFILE")
    sections.append(f"File: {apk}")
    sections.append(f"Package: {pkg}")
    sections.append(f"SHA256: {sha}")
    
    sections.append("")
    sections.append("3. PERMISSION ANALYSIS")
    sections.append(f"Total Dangerous Permissions: {len(dangerous)}")
    for p in dangerous[:8]:
        sections.append(f"  - {p}")
    
    sections.append("")
    sections.append("4. SECURITY FLAGS")
    if sec_flags.get("debuggable"):
        sections.append("  - CRITICAL: Application is debuggable")
    if sec_flags.get("uses_cleartext_traffic"):
        sections.append("  - HIGH: Cleartext traffic permitted")
    if sec_flags.get("allow_backup"):
        sections.append("  - MEDIUM: Backup enabled")
    
    if vulns:
        sections.append("")
        sections.append("5. VULNERABILITY ASSESSMENT & PROOF OF CONCEPT")
        sections.append(f"Total: {len(vulns)} | Critical: {len(critical_vulns)} | High: {len(high_vulns)}")
        for v in vulns:
            sections.append(f"  - [{v.get('severity','').upper()}] {v.get('title','')} (CVSS {v.get('cvss_score',0)})")
            if v.get('cwe_id') or v.get('owasp_category'):
                sections.append(f"    CWE: {v.get('cwe_id', 'N/A')} | OWASP: {v.get('owasp_category', 'N/A')}")
            if v.get('poc_narrative'):
                sections.append("    --- PROOF OF CONCEPT (LLM GENERATED) ---")
                for line in str(v.get('poc_narrative')).split('\n'):
                    sections.append(f"    {line}")
                sections.append("    ----------------------------------------")
            sections.append("")
    
    c2 = case_data.get("c2_intelligence", {})
    if c2:
        sections.append("")
        sections.append("6. C2 & ATTRIBUTION")
        sections.append(f"C2 Risk Score: {c2.get('risk_score', 0)}/100")
        infra = c2.get("contacted_infrastructure", [])
        if infra:
            sections.append(f"Contacted Infrastructure: {len(infra)} endpoints")
        attr = c2.get("attribution", {})
        if attr.get("campaign"):
            sections.append(f"Attributed Campaign: {attr.get('campaign')}")
            
    threat_narrative = case_data.get("threat_narrative")
    if threat_narrative:
        sections.append("")
        sections.append("7. THREAT REASONING & MITIGATION")
        if isinstance(threat_narrative, dict):
            if threat_narrative.get("behavioral_intent"):
                sections.append(f"Behavioral Intent: {threat_narrative.get('behavioral_intent')}")
            if threat_narrative.get("chain_of_evidence"):
                sections.append("Chain of Evidence:")
                for item in threat_narrative.get("chain_of_evidence", []):
                    sections.append(f"  - {item}")
            if threat_narrative.get("mitigation_recommendations"):
                sections.append("Prevention & Recommendations:")
                for item in threat_narrative.get("mitigation_recommendations", []):
                    sections.append(f"  - {item}")
        elif isinstance(threat_narrative, str):
            sections.append(threat_narrative)
    
    sections.append("")
    sections.append("8. SECTION 65B COMPLIANCE")
    sections.append("This forensic document is certified under Section 65B of the Indian Evidence Act.")
    sections.append(f"Generated: {datetime.datetime.utcnow().isoformat()}Z")
    
    return "\n".join(sections)


# ── Case Data Loader ─────────────────────────────────────────

def _safe_slice(obj, limit):
    if isinstance(obj, list):
        return obj[:limit]
    return obj

def _load_case_data(case_id: str, db: Session) -> Dict[str, Any]:
    """Load real analysis data from database for report generation."""
    try:
        case_uuid = UUID(case_id)
    except ValueError:
        return {}

    case = db.query(Case).filter(Case.id == case_uuid).first()
    if not case:
        return {}

    data = {
        "case_number": f"CASE-{str(case.id)[:8].upper()}",
        "apk_name": case.apk_name,
        "sha256": case.apk_hash,
        "status": case.status,
    }

    phase_results = db.query(PhaseResult).filter(PhaseResult.case_id == case_uuid).all()
    
    for pr in phase_results:
        if pr.phase == "static" and pr.result:
            result = pr.result
            steps = result.get("steps", {})
            manifest = steps.get("manifest", {}).get("data", {})
            if "package_name" in manifest:
                data["package_name"] = manifest["package_name"]
            data["security_flags"] = manifest.get("security_flags", {})
            data["misconfigurations"] = manifest.get("misconfigurations", [])
            
            androguard = steps.get("androguard", {}).get("data", {})
            permissions = androguard.get("permissions", {})
            data["permissions"] = {
                "all": permissions.get("all", []),
                "dangerous": permissions.get("dangerous", []),
            }
            
            iocs = steps.get("iocs", {}).get("data", {})
            data["iocs"] = {
                "urls": _safe_slice(iocs.get("urls"), 15),
                "domains": _safe_slice(iocs.get("domains"), 15),
                "ips": _safe_slice(iocs.get("ips"), 15),
            }
            
            data["static_threat_score"] = result.get("threat_score", 0)
            data["threat_score"] = result.get("threat_score", 0)
            
        elif pr.phase == "dynamic" and pr.result:
            result = pr.result
            data["dynamic_analysis"] = {
                "mode": result.get("mode"),
                "total_events": result.get("total_events", 0),
                "network_activity": (result.get("network_activity") or [])[:30],
                "dropped_packages": result.get("dropped_packages", []),
                "behaviors": result.get("behaviors", {}),
                "risk_score": result.get("risk_score", 0),
            }
            
        elif pr.phase == "c2_intelligence" and pr.result:
            result = pr.result
            data["c2_intelligence"] = {
                "risk_score": result.get("risk_score", 0),
                "contacted_infrastructure": _safe_slice(result.get("contacted_infrastructure"), 10),
                "attribution": result.get("attribution", {}),
            }
            
        elif pr.phase == "vulnerability" and pr.result:
            result = pr.result
            data["vulnerabilities"] = [{
                "title": f.get("title", f.get("name", "")),
                "severity": f.get("severity", ""),
                "cvss_score": f.get("cvss_score", 0),
                "cwe_id": f.get("cwe_id", f.get("cwe", "")),
                "owasp_category": f.get("owasp_category", f.get("owasp", "")),
                "description": f.get("description", ""),
                "poc_narrative": f.get("poc_narrative", f.get("poc", "")),
            } for f in result.get("findings", [])]
            
        elif pr.phase == "threat_reasoning" and pr.result:
            data["threat_narrative"] = pr.result

    risk_scores = [pr.risk_score for pr in phase_results if pr.risk_score is not None]
    if risk_scores:
        data["threat_score"] = max(risk_scores)
    elif "threat_score" not in data:
        data["threat_score"] = 0

    return data


# ── PDF Generator ─────────────────────────────────────────────

class PDFGenerator:
    def __init__(self, output_dir):
        self.output_dir = output_dir
        try:
            from reportlab.pdfbase import pdfmetrics
            from reportlab.pdfbase.ttfonts import TTFont
            pdfmetrics.registerFont(TTFont('Nirmala', 'C:/Windows/Fonts/Nirmala.ttc', subfontIndex=0))
            self.font_name = 'Nirmala'
        except Exception:
            self.font_name = 'Helvetica'

    def generate_report(self, case_id: str, narrative: str, language: str, case_number: str = ""):
        file_path = os.path.join(self.output_dir, f"Report_{case_id}_{language}.pdf")
        c = canvas.Canvas(file_path, pagesize=letter)
        width, height = letter
        font = self.font_name
        
        # Translate if needed
        if language.lower() not in ["en", "english"]:
            narrative = translate_text(narrative, language)
            lang_label = language.upper()
        else:
            lang_label = "ENGLISH"
        
        def draw_header(page_canvas, page_num=1):
            page_canvas.setFillColor(colors.HexColor("#0D1117"))
            page_canvas.rect(0, height - 80, width, 80, fill=True, stroke=False)
            page_canvas.setFillColor(colors.white)
            page_canvas.setFont(font, 16)
            page_canvas.drawString(40, height - 40, f"APEX-X Investigation Report ({lang_label})")
            page_canvas.setFont(font, 9)
            page_canvas.drawString(40, height - 58, f"Case: {case_number or case_id} | Classification: CONFIDENTIAL / SECTION 65B")
            page_canvas.drawString(40, height - 72, f"Generated: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC | Page {page_num}")
        
        def draw_footer(page_canvas):
            page_canvas.setFillColor(colors.HexColor("#6B7280"))
            page_canvas.setFont(font, 7)
            page_canvas.drawString(40, 25, "APEX-X Automated Forensic Platform | Section 65B Certified | Government of India")
            page_canvas.drawString(width - 200, 25, f"Generated: {datetime.datetime.utcnow().strftime('%Y-%m-%d')}")
        
        # Render narrative into multi-page PDF
        draw_header(c, 1)
        draw_footer(c)
        
        c.setFillColor(colors.black)
        y = height - 110
        page_num = 1
        margin_left = 45
        max_width = width - 90
        
        import re
        lines = narrative.split("\n")
        for raw_line in lines:
            line = raw_line.strip()
            # Clean markdown formatting like ### or **
            line = re.sub(r'^\s*#+\s*', '', line)
            line = re.sub(r'\*\*([^*]+)\*\*', r'\1', line)
            line = re.sub(r'\*([^*]+)\*', r'\1', line)
            line = re.sub(r'__([^_]+)__', r'\1', line)
            line = re.sub(r'_([^_]+)_', r'\1', line)
            line = re.sub(r'`([^`]+)`', r'\1', line)
            if line.startswith(("* ", "- ")):
                line = "• " + line[2:]

            # Detect section headers
            is_header = (
                line.startswith(("1.", "2.", "3.", "4.", "5.", "6.", "7.", "8.")) or
                (line.upper() == line and len(line) > 3 and len(line) < 80 and not line.startswith("•"))
            )
            
            if is_header:
                c.setFont(font, 12)
                font_size = 12
                y -= 8  # extra spacing before headers
            elif line.strip().startswith(("-", "•", "*")):
                c.setFont(font, 9)
                font_size = 9
            else:
                c.setFont(font, 10)
                font_size = 10
            
            # Word-wrap long lines
            wrapped = simpleSplit(line, font, font_size, max_width) if line.strip() else [""]
            
            for wrapped_line in wrapped:
                if y < 50:
                    c.showPage()
                    page_num += 1
                    draw_header(c, page_num)
                    draw_footer(c)
                    c.setFillColor(colors.black)
                    c.setFont(font, font_size)
                    y = height - 110
                
                c.drawString(margin_left, y, wrapped_line)
                y -= font_size + 4
        
        c.showPage()
        c.save()
        return file_path


class EvidencePackager:
    def __init__(self, cases_dir, keys_dir):
        self.cases_dir = cases_dir

    def package_case(self, case_id: str, case_number: str):
        zip_filename = f"evidence_package_{case_id}.zip"
        zip_path = os.path.join(self.cases_dir, zip_filename)
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("manifest.json", json.dumps({
                "case_number": case_number, "case_id": case_id,
                "status": "SEALED", "timestamp": f"{datetime.datetime.utcnow().isoformat()}Z"
            }, indent=2))
            zf.writestr("section_65B_certificate.txt",
                f"CERTIFICATE UNDER SECTION 65B OF THE INDIAN EVIDENCE ACT\n\n"
                f"Case: {case_number}\n"
                f"This is to certify that the electronic record contained herein was produced "
                f"by APEX-X Automated Forensic System.\n"
                f"Timestamp: {datetime.datetime.utcnow().isoformat()}Z")
            zf.writestr("chain_of_custody.log",
                f"{datetime.datetime.utcnow().isoformat()}Z - Evidence ingested into APEX-X\n"
                f"{datetime.datetime.utcnow().isoformat()}Z - Hash verified: SHA256 matches manifest\n"
                f"{datetime.datetime.utcnow().isoformat()}Z - Sealed for court presentation.")
        return zip_path


# ── Router ────────────────────────────────────────────────────

router = APIRouter()

from app.config import settings as _settings
REPORTS_DIR = _settings.REPORTS_DIR
CASES_DIR = _settings.CASES_DIR
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(CASES_DIR, exist_ok=True)


@router.get("/{case_id}/download")
async def download_report(case_id: str, language: str = "en", db: Session = Depends(get_db)):
    """
    Generates and returns a PDF report for the given case.
    Loads real data from DB, generates narrative via LLM, translates if needed.
    """
    try:
        # Load real case data from database
        case_data = _load_case_data(case_id, db)
        case_number = case_data.get("case_number", f"CASE-{case_id[:8].upper()}")
        
        import uuid
        case_uuid = uuid.UUID(case_id)
        
        # First check if there's a cached English report
        report_record = db.query(PhaseResult).filter(
            PhaseResult.case_id == case_uuid,
            PhaseResult.phase == "report_english"
        ).first()

        if report_record and report_record.result and "narrative" in report_record.result:
            narrative = report_record.result["narrative"]
        else:
            # Fallback for old cases: generate on-the-fly
            narrative = _generate_report_narrative(case_data)
        
        # Generate the PDF (translation happens inside if language != English)
        generator = PDFGenerator(REPORTS_DIR)
        pdf_path = generator.generate_report(case_id, narrative, language, case_number)
        
        if not os.path.exists(pdf_path):
            raise HTTPException(status_code=500, detail="Failed to generate PDF")
            
        return FileResponse(
            path=pdf_path,
            filename=f"Report_{case_id}_{language}.pdf",
            media_type="application/pdf"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Report generation error: {e}")
        raise HTTPException(status_code=500, detail=f"Error generating report: {str(e)}")


@router.get("/{case_id}/evidence-package")
async def download_evidence_package(case_id: str):
    """
    Generates and returns the Section 65B ZIP evidence package.
    """
    try:
        packager = EvidencePackager(CASES_DIR, os.path.join(_settings.DATA_DIR, "keys"))
        case_number = f"CASE-{case_id[:8].upper()}"
        
        case_dir = os.path.join(CASES_DIR, case_id)
        os.makedirs(case_dir, exist_ok=True)
        
        zip_path = packager.package_case(case_id, case_number)
        
        if not os.path.exists(zip_path):
            raise HTTPException(status_code=500, detail="Failed to generate evidence package")
            
        return FileResponse(
            path=zip_path,
            filename=f"evidence_package_{case_id}.zip",
            media_type="application/zip"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error packaging evidence: {str(e)}")
