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

    # Delete related records to prevent foreign key constraint violations
    try:
        from app.models.database import AuditLog
        db.query(AuditLog).filter(AuditLog.case_id == case_id).delete()
    except Exception as e:
        logger.debug(f"AuditLog delete skipped: {e}")

    try:
        from app.models.database import EvidenceRecord
        db.query(EvidenceRecord).filter(EvidenceRecord.case_id == case_id).delete()
    except Exception as e:
        logger.debug(f"EvidenceRecord delete skipped: {e}")

    try:
        from app.models.database import BatchCase
        db.query(BatchCase).filter(BatchCase.case_id == case_id).delete()
    except Exception as e:
        logger.debug(f"BatchCase delete skipped: {e}")

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
    from app.config import settings as _s
    cdir = os.path.join(_s.CASES_DIR, case_id_str)
    if os.path.exists(cdir):
        shutil.rmtree(cdir, ignore_errors=True)
        logger.info(f"Deleted case directory: {cdir}")

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
    from app.services.case_service import compute_threat_score
    cases = db.query(Case).all()
    for case in cases:
        case.threat_score = compute_threat_score(case.phase_results)
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
        
    from app.services.case_service import compute_threat_score
    case.threat_score = compute_threat_score(case.phase_results)
    return case

@router.get("/{case_id}/dynamic/pcap")
def download_dynamic_pcap(case_id: UUID, db: Session = Depends(get_db)):
    """Download the packet capture recorded during dynamic analysis (opens in Wireshark)."""
    import os
    from fastapi.responses import FileResponse
    from app.config import settings as _s
    if not db.query(Case).filter(Case.id == case_id).first():
        raise HTTPException(status_code=404, detail="Case not found")
    case_dir = os.path.join(_s.CASES_DIR, str(case_id))
    candidates = [
        os.path.join(case_dir, "dynamic_analysis", "capture.pcap"),          # automated emulator run
        os.path.join(case_dir, "pentest_analysis", "network_capture.pcap"),  # manual analyst session
    ]
    for path in candidates:
        if os.path.isfile(path) and os.path.getsize(path) > 0:
            return FileResponse(path, media_type="application/vnd.tcpdump.pcap",
                                filename=f"apexx_{str(case_id)[:8]}_capture.pcap")
    raise HTTPException(status_code=404, detail="No packet capture recorded for this case")


@router.get("/{case_id}/dynamic/status")
def get_dynamic_status(case_id: UUID, db: Session = Depends(get_db)):
    """Live stage of an in-progress dynamic analysis (emulator boot, install, execution...)."""
    import os, json
    from app.services.dynamic_service import is_running, DATA_DIR
    path = os.path.join(DATA_DIR, str(case_id), "dynamic_analysis", "status.json")
    status_data = {}
    try:
        with open(path) as f:
            status_data = json.load(f)
    except Exception:
        pass
    return {"running": is_running(str(case_id)), **status_data}


@router.get("/dynamic/emulator")
def get_emulator_status():
    from app.engines.dynamic.emulator_manager import emulator_status
    return emulator_status()


@router.post("/dynamic/emulator/boot")
def boot_emulator():
    """Boot the Android emulator (if not already running) so no USB device is needed."""
    import threading
    from app.engines.dynamic.emulator_manager import ensure_emulator, emulator_status
    status_now = emulator_status()
    if not status_now["booted"]:
        threading.Thread(target=ensure_emulator, daemon=True).start()
    return {**status_now, "booting": not status_now["booted"]}


@router.post("/{case_id}/dynamic/run")
def run_dynamic_analysis_on_demand(case_id: UUID, db: Session = Depends(get_db)):
    """
    On-demand trigger to boot the emulator and run dynamic analysis.
    """
    import logging
    
    logger = logging.getLogger(__name__)
    
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found"
        )
        
    from app.services.dynamic_service import start_dynamic_in_background, is_running
    if is_running(str(case.id)):
        return {"status": "already_running", "message": "Dynamic analysis is already in progress"}
    start_dynamic_in_background(str(case.id), case.apk_name)
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

    from app.config import settings as _s
    DATA_DIR = _s.CASES_DIR
    case_dir = os.path.join(DATA_DIR, str(case_id))
    from app.utils.file_utils import resolve_analysis_apk
    apk_path = resolve_analysis_apk(case_dir, case.apk_name)

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
            from app.config import settings as _s
            case_dir = os.path.join(_s.CASES_DIR, cid)
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

    from app.config import settings as _s
    DATA_DIR = _s.CASES_DIR
    case_dir = os.path.join(DATA_DIR, str(case_id))
    from app.utils.file_utils import resolve_analysis_apk
    apk_path = resolve_analysis_apk(case_dir, case.apk_name)

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



