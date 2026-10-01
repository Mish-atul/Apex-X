from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from uuid import UUID

from app.api.dependencies import get_db
from app.models.database import Case, PhaseResult
from app.models.schemas import Case as CaseSchema

router = APIRouter()


@router.delete("/{case_id}")
def delete_case(case_id: UUID, db: Session = Depends(get_db)):
    """
    Delete a case and all its associated data (phase results, files on disk).
    """
    import os
    import shutil
    import logging

    logger = logging.getLogger(__name__)

    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    apk_name = case.apk_name
    case_id_str = str(case_id)

    # Delete phase results
    db.query(PhaseResult).filter(PhaseResult.case_id == case_id).delete()

    # Delete fingerprints if table exists
    try:
        from app.models.database import ApkFingerprint
        db.query(ApkFingerprint).filter(ApkFingerprint.case_id == case_id).delete()
    except Exception:
        pass

    # Delete the case record
    db.delete(case)
    db.commit()

    # Delete case directory from disk
    DATA_DIR = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "data", "cases"
    )
    case_dir = os.path.join(DATA_DIR, case_id_str)
    if os.path.exists(case_dir):
        shutil.rmtree(case_dir)
        logger.info(f"Deleted case directory: {case_dir}")

    logger.info(f"Case {case_id_str} ({apk_name}) deleted successfully")
    return {"status": "deleted", "case_id": case_id_str, "apk_name": apk_name}

@router.get("/threat-map")
def get_threat_map(db: Session = Depends(get_db)):
    """
    Aggregate IP geolocation data from all analyzed C2 results
    for the interactive world threat map visualization.
    """
    markers = []
    arcs = []
    seen_ips = set()

    # Get all C2 intelligence phase results
    c2_phases = db.query(PhaseResult).filter(PhaseResult.phase == "c2_intelligence").all()

    for phase in c2_phases:
        if not phase.result:
            continue

        result = phase.result
        nodes = result.get("nodes", [])
        attribution = result.get("attribution", {})
        case = db.query(Case).filter(Case.id == phase.case_id).first()
        case_name = case.apk_name if case else "Unknown"
        target_region = attribution.get("target_region", "India")

        # Default origin coordinates (India)
        origin_coords = {"lat": 20.5937, "lng": 78.9629}
        region_coords = {
            "India": {"lat": 20.5937, "lng": 78.9629},
            "China": {"lat": 35.8617, "lng": 104.1954},
            "Russia": {"lat": 61.524, "lng": 105.3188},
            "Brazil": {"lat": -14.235, "lng": -51.9253},
            "Global": {"lat": 20.5937, "lng": 78.9629},
        }
        origin = region_coords.get(target_region, origin_coords)

        for node in nodes:
            if node.get("type") != "ip":
                continue

            meta = node.get("metadata", {})
            lat = meta.get("lat", 0)
            lng = meta.get("lng", 0)
            ip = node.get("label", "")

            if not lat and not lng:
                continue
            if ip in seen_ips:
                continue
            seen_ips.add(ip)

            markers.append({
                "ip": ip,
                "lat": lat,
                "lng": lng,
                "country": meta.get("country", ""),
                "city": meta.get("city", ""),
                "org": meta.get("asn", ""),
                "classification": meta.get("classification", "unknown"),
                "risk": node.get("risk", "medium"),
                "case_name": case_name,
            })

            arcs.append({
                "from": origin,
                "to": {"lat": lat, "lng": lng},
                "case_name": case_name,
                "classification": meta.get("classification", "unknown"),
            })

    return {"markers": markers, "arcs": arcs}

@router.get("/", response_model=List[CaseSchema])
def get_cases(db: Session = Depends(get_db)):
    """
    Retrieve all cases and compute their threat_score from phase results.
    """
    cases = db.query(Case).all()
    for case in cases:
        # Calculate max risk score across all phases
        risk_scores = [p.risk_score for p in case.phase_results if p.risk_score is not None]
        case.threat_score = max(risk_scores) if risk_scores else 0
    return cases

@router.get("/{case_id}", response_model=CaseSchema)
def get_case(case_id: UUID, db: Session = Depends(get_db)):
    """
    Retrieve details for a specific case by ID.
    """
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found"
        )
        
    risk_scores = [p.risk_score for p in case.phase_results if p.risk_score is not None]
    case.threat_score = max(risk_scores) if risk_scores else 0
    return case

@router.post("/{case_id}/dynamic/run")
def run_dynamic_analysis_on_demand(case_id: UUID, db: Session = Depends(get_db)):
    """
    On-demand trigger to boot the emulator and run dynamic analysis.
    """
    import os
    import threading
    import logging
    from app.models.database import PhaseResult
    
    logger = logging.getLogger(__name__)
    
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found"
        )
        
    def _run_emulator_bg(cid: str, apk_name: str):
        from app.models.session import SessionLocal
        from app.engines.dynamic import run_full_dynamic_analysis
        from datetime import datetime
        import uuid as _uuid
        
        db_bg = SessionLocal()
        try:
            case_uuid = _uuid.UUID(cid)
            DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "cases")
            case_dir = os.path.join(DATA_DIR, cid)
            apk_path = os.path.join(case_dir, apk_name)
            
            logger.info(f"Starting ON DEMAND dynamic analysis for case {cid}")
            # Emulator should already be running (user launched via batch file)
            # Install APK, open it, collect data for 90s while user browses
            dynamic_result = run_full_dynamic_analysis(apk_path, case_dir, duration=90, force_emulator=False)
            
            def _parse_dt(val):
                if val is None:
                    return datetime.utcnow()
                if isinstance(val, str):
                    try:
                        return datetime.fromisoformat(val.replace("Z", "+00:00"))
                    except:
                        return datetime.utcnow()
                return val
            
            # Delete old dynamic phase if exists
            old_phase = db_bg.query(PhaseResult).filter(PhaseResult.case_id == case_uuid, PhaseResult.phase == "dynamic").first()
            if old_phase:
                db_bg.delete(old_phase)
                
            dynamic_phase = PhaseResult(
                case_id=case_uuid,
                phase="dynamic",
                result=dynamic_result,
                risk_score=dynamic_result.get("risk_score", 0),
                completed_at=_parse_dt(dynamic_result.get("completed_at"))
            )
            db_bg.add(dynamic_phase)
            db_bg.commit()
            
            # Re-run C2 Intelligence with new dynamic network data
            from app.engines.c2 import run_full_c2_intelligence
            logger.info("Updating C2 Intelligence with dynamic findings...")
            c2_result = run_full_c2_intelligence(apk_path, case_dir, cid)
            old_c2 = db_bg.query(PhaseResult).filter(PhaseResult.case_id == case_uuid, PhaseResult.phase == "c2_intelligence").first()
            if old_c2: db_bg.delete(old_c2)
            db_bg.add(PhaseResult(case_id=case_uuid, phase="c2_intelligence", result=c2_result, risk_score=c2_result.get("risk_score", 0), completed_at=_parse_dt(c2_result.get("completed_at"))))
            db_bg.commit()
            
            # Re-run Vulnerability scan with all 3 reports (static, dynamic, c2)
            from app.engines.vulnerability import run_vulnerability_scan
            logger.info("Updating Vulnerabilities with full intelligence...")
            vuln_result = run_vulnerability_scan(case_dir, cid)
            old_vuln = db_bg.query(PhaseResult).filter(PhaseResult.case_id == case_uuid, PhaseResult.phase == "vulnerability").first()
            if old_vuln: db_bg.delete(old_vuln)
            db_bg.add(PhaseResult(case_id=case_uuid, phase="vulnerability", result=vuln_result, risk_score=vuln_result.get("risk_score", 0), completed_at=_parse_dt(vuln_result.get("completed_at"))))
            db_bg.commit()
            
            logger.info("On-demand dynamic analysis and intelligence correlation complete!")
        except Exception as e:
            logger.error(f"On-demand dynamic analysis failed: {e}")
        finally:
            db_bg.close()

    thread = threading.Thread(
        target=_run_emulator_bg,
        args=(str(case.id), case.apk_name),
        daemon=True
    )
    thread.start()
    
    return {"status": "started", "message": "Emulator analysis triggered"}


# ── Manual Penetration Testing Endpoints ────────────────────────────

@router.get("/{case_id}/pentest/devices")
def scan_pentest_devices(case_id: UUID, db: Session = Depends(get_db)):
    """
    Scan for physical Android devices connected via USB.
    """
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    from app.engines.dynamic.device_monitor import scan_usb_devices
    devices = scan_usb_devices()

    return {"devices": devices, "count": len(devices)}


@router.post("/{case_id}/pentest/start")
def start_pentest_session(
    case_id: UUID,
    body: dict = None,
    db: Session = Depends(get_db)
):
    """
    Start a manual penetration testing monitoring session on a physical device.
    Body: { "device_serial": "XYZ123" }
    """
    import os

    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    if not body or not body.get("device_serial"):
        raise HTTPException(status_code=400, detail="device_serial is required")

    device_serial = body["device_serial"]

    DATA_DIR = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "data", "cases"
    )
    case_dir = os.path.join(DATA_DIR, str(case_id))
    apk_path = os.path.join(case_dir, case.apk_name)

    from app.engines.dynamic.device_monitor import start_monitoring_session
    result = start_monitoring_session(
        device_serial=device_serial,
        case_dir=case_dir,
        case_id=str(case_id),
        apk_path=apk_path,
    )

    return result


@router.get("/{case_id}/pentest/status")
def get_pentest_status(case_id: UUID, db: Session = Depends(get_db)):
    """
    Get live status of the active monitoring session for a case.
    """
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    from app.engines.dynamic.device_monitor import (
        get_active_session_for_case,
        get_session_status,
    )
    session_id = get_active_session_for_case(str(case_id))
    if not session_id:
        return {"status": "no_active_session"}

    return get_session_status(session_id)


@router.post("/{case_id}/pentest/stop")
def stop_pentest_session(case_id: UUID, db: Session = Depends(get_db)):
    """
    Stop the monitoring session, generate report, save to DB,
    and trigger C2 + Vulnerability re-analysis with the new data.
    """
    import os
    import threading
    import logging
    from datetime import datetime

    logger = logging.getLogger(__name__)

    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    from app.engines.dynamic.device_monitor import (
        get_active_session_for_case,
        stop_monitoring_session,
    )
    session_id = get_active_session_for_case(str(case_id))
    if not session_id:
        raise HTTPException(status_code=400, detail="No active monitoring session")

    def _finalize_bg(cid: str, sid: str, apk_name: str):
        from app.models.session import SessionLocal
        import uuid as _uuid

        db_bg = SessionLocal()
        try:
            case_uuid = _uuid.UUID(cid)

            # Stop monitoring and get result
            dynamic_result = stop_monitoring_session(sid)

            def _parse_dt(val):
                if val is None:
                    return datetime.utcnow()
                if isinstance(val, str):
                    try:
                        return datetime.fromisoformat(val.replace("Z", "+00:00"))
                    except Exception:
                        return datetime.utcnow()
                return val

            # Delete old dynamic phase if exists
            old_phase = db_bg.query(PhaseResult).filter(
                PhaseResult.case_id == case_uuid,
                PhaseResult.phase == "dynamic"
            ).first()
            if old_phase:
                db_bg.delete(old_phase)

            dynamic_phase = PhaseResult(
                case_id=case_uuid,
                phase="dynamic",
                result=dynamic_result,
                risk_score=dynamic_result.get("risk_score", 0),
                completed_at=_parse_dt(dynamic_result.get("completed_at"))
            )
            db_bg.add(dynamic_phase)
            db_bg.commit()

            # Re-run C2 Intelligence with new network data
            DATA_DIR = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                "data", "cases"
            )
            case_dir = os.path.join(DATA_DIR, cid)
            apk_path = os.path.join(case_dir, apk_name)

            from app.engines.c2 import run_full_c2_intelligence
            logger.info("Updating C2 Intelligence with pentest findings...")
            c2_result = run_full_c2_intelligence(apk_path, case_dir, cid)
            old_c2 = db_bg.query(PhaseResult).filter(
                PhaseResult.case_id == case_uuid,
                PhaseResult.phase == "c2_intelligence"
            ).first()
            if old_c2:
                db_bg.delete(old_c2)
            db_bg.add(PhaseResult(
                case_id=case_uuid, phase="c2_intelligence",
                result=c2_result, risk_score=c2_result.get("risk_score", 0),
                completed_at=_parse_dt(c2_result.get("completed_at"))
            ))
            db_bg.commit()

            # Re-run Vulnerability scan
            from app.engines.vulnerability import run_vulnerability_scan
            logger.info("Updating Vulnerabilities with pentest intelligence...")
            vuln_result = run_vulnerability_scan(case_dir, cid)
            old_vuln = db_bg.query(PhaseResult).filter(
                PhaseResult.case_id == case_uuid,
                PhaseResult.phase == "vulnerability"
            ).first()
            if old_vuln:
                db_bg.delete(old_vuln)
            db_bg.add(PhaseResult(
                case_id=case_uuid, phase="vulnerability",
                result=vuln_result, risk_score=vuln_result.get("risk_score", 0),
                completed_at=_parse_dt(vuln_result.get("completed_at"))
            ))
            db_bg.commit()

            logger.info("Pentest session finalized with C2 + Vuln re-analysis!")
        except Exception as e:
            logger.error(f"Pentest finalization failed: {e}")
        finally:
            db_bg.close()

    thread = threading.Thread(
        target=_finalize_bg,
        args=(str(case.id), session_id, case.apk_name),
        daemon=True
    )
    thread.start()

    return {"status": "stopping", "message": "Monitoring stopped. Report is being generated."}


@router.post("/{case_id}/pentest/clean")
def clean_pentest_device(case_id: UUID, body: dict = None, db: Session = Depends(get_db)):
    """
    Manually clean up / uninstall all test APKs (target APK and any child/dropper APKs)
    from the connected device.
    Body can optionally contain { "device_serial": "XYZ" }.
    """
    import os
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    device_serial = (body or {}).get("device_serial")
    if not device_serial:
        # Fall back to first available USB device
        from app.engines.dynamic.device_monitor import scan_usb_devices
        devices = scan_usb_devices()
        ready = [d for d in devices if d.get("status") == "ready"]
        if ready:
            device_serial = ready[0]["serial"]
        else:
            raise HTTPException(status_code=400, detail="No connected Android device found to clean")

    DATA_DIR = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "data", "cases"
    )
    case_dir = os.path.join(DATA_DIR, str(case_id))
    apk_path = os.path.join(case_dir, case.apk_name)

    from app.engines.dynamic import vm_orchestrator
    target_package = ""
    if os.path.exists(apk_path):
        target_package = vm_orchestrator.get_package_name(apk_path) or ""

    from app.engines.dynamic.device_monitor import cleanup_device_for_case
    result = cleanup_device_for_case(case_dir, device_serial, target_package)
    return result


@router.post("/{case_id}/pentest/uninstall-package")
def uninstall_package(case_id: UUID, body: dict, db: Session = Depends(get_db)):
    """
    Uninstall a specific package (parent, child dropper, or any detected application)
    from the connected device.
    Body must contain { "package_name": "..." } and optionally { "device_serial": "..." }.
    """
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    package_name = body.get("package_name")
    if not package_name:
        raise HTTPException(status_code=400, detail="package_name is required")

    device_serial = body.get("device_serial")
    if not device_serial:
        from app.engines.dynamic.device_monitor import scan_usb_devices
        devices = scan_usb_devices()
        ready = [d for d in devices if d.get("status") == "ready"]
        if ready:
            device_serial = ready[0]["serial"]
        else:
            raise HTTPException(status_code=400, detail="No connected Android device found")

    from app.engines.dynamic.device_monitor import uninstall_single_package
    result = uninstall_single_package(device_serial, package_name)
    return result



