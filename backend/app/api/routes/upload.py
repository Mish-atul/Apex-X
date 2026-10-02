from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.api import dependencies
from app.api.middleware.rbac import get_current_user
from app.services.hash_service import calculate_sha256, append_to_manifest
from app.utils.file_utils import (
    is_valid_apk, save_upload_file, is_allowed_upload, is_bundle_filename,
    is_valid_bundle, extract_bundle,
)
from app.services.audit_service import log_action
from app.models.database import Case, PhaseResult, User
from app.models.schemas import Case as CaseSchema
import uuid
import os
import shutil
import logging
import threading

logger = logging.getLogger(__name__)

router = APIRouter()

# Data directory for local storage (single source of truth)
from app.config import settings as _settings
DATA_DIR = _settings.CASES_DIR
os.makedirs(DATA_DIR, exist_ok=True)


def _run_analysis_sync(case_id: str, apk_name: str, apk_hash: str):
    """Run static analysis synchronously in a background thread (no Redis/Celery needed)."""
    from app.models.session import SessionLocal
    from app.engines.static import run_full_static_analysis
    from datetime import datetime
    import uuid as _uuid

    case_uuid = _uuid.UUID(case_id) if isinstance(case_id, str) else case_id

    db = SessionLocal()
    try:
        case = db.query(Case).filter(Case.id == case_uuid).first()
        if not case:
            logger.error(f"Case {case_id} not found for analysis")
            return

        case.status = "analyzing"
        db.commit()

        case_dir = os.path.join(DATA_DIR, str(case_id))
        from app.utils.file_utils import resolve_analysis_apk
        apk_path = resolve_analysis_apk(case_dir, apk_name)

        if not os.path.exists(apk_path):
            logger.error(f"APK not found: {apk_path}")
            case.status = "failed"
            db.commit()
            return

        # Run static analysis
        logger.info(f"Starting static analysis for case {case_id}")
        static_result = run_full_static_analysis(apk_path, case_dir)

        def _parse_dt(val):
            """Convert ISO string to datetime object for SQLite."""
            if val is None:
                return datetime.utcnow()
            if isinstance(val, str):
                try:
                    return datetime.fromisoformat(val.replace("Z", "+00:00")).replace(tzinfo=None)
                except Exception:
                    return datetime.utcnow()
            return val
        
        # Update case metadata with results
        manifest_data = static_result.get("steps", {}).get("manifest", {}).get("data", {})
        if manifest_data.get("package_name"):
            case.package_name = manifest_data["package_name"]

        # Save static phase result to DB
        phase_record = PhaseResult(
            case_id=case_uuid,
            phase="static",
            result=static_result,
            risk_score=static_result.get("risk_score", 0),
            completed_at=_parse_dt(static_result.get("completed_at"))
        )
        db.add(phase_record)
        
        # Dynamic analysis runs automatically on the emulator once static completes
        dynamic_phase = PhaseResult(
            case_id=case_uuid,
            phase="dynamic",
            result={"status": "queued", "mode": "emulator", "message": "Queued for emulator execution"},
            risk_score=0,
            completed_at=datetime.utcnow()
        )
        db.add(dynamic_phase)

        # Try C2 intelligence
        try:
            from app.engines.c2 import run_full_c2_intelligence
            c2_result = run_full_c2_intelligence(apk_path, case_dir, str(case_id))
            c2_phase = PhaseResult(
                case_id=case_uuid, phase="c2_intelligence",
                result=c2_result, risk_score=c2_result.get("risk_score", 0),
                completed_at=_parse_dt(c2_result.get("completed_at"))
            )
            db.add(c2_phase)
        except Exception as e:
            logger.warning(f"C2 intelligence skipped: {e}")

        # Try vulnerability scan
        try:
            from app.engines.vulnerability import run_vulnerability_scan
            vuln_result = run_vulnerability_scan(case_dir, str(case_id))
            vuln_phase = PhaseResult(
                case_id=case_uuid, phase="vulnerability",
                result=vuln_result, risk_score=vuln_result.get("risk_score", 0),
                completed_at=_parse_dt(vuln_result.get("completed_at"))
            )
            db.add(vuln_phase)
        except Exception as e:
            logger.warning(f"Vulnerability scan skipped: {e}")

        case.status = "completed"
        db.commit()
        logger.info(f"Analysis completed for case {case_id}, risk_score={static_result.get('risk_score')}")

        if os.environ.get("APEX_AUTO_DYNAMIC", "1") == "1":
            from app.services.dynamic_service import start_dynamic_in_background
            start_dynamic_in_background(str(case_id), apk_name)

    except Exception as e:
        logger.error(f"Analysis failed for case {case_id}: {e}")
        db.rollback()
        case = db.query(Case).filter(Case.id == case_uuid).first()
        if case:
            case.status = "failed"
            db.commit()
    finally:
        db.close()


@router.post("/upload/", response_model=CaseSchema, status_code=status.HTTP_201_CREATED)
async def upload_apk(
    file: UploadFile = File(...),
    db: Session = Depends(dependencies.get_db),
    current_user: User = Depends(get_current_user)
):
    file.filename = os.path.basename(file.filename or "")
    if not is_allowed_upload(file.filename):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file type. Allowed: .apk, .xapk, .apks, .apkm."
        )
    is_bundle = is_bundle_filename(file.filename)
    
    # 1. Hash the uploaded file
    await file.seek(0)
    apk_hash = calculate_sha256(file.file)
    await file.seek(0)
    
    # Check if a case with this hash already exists
    existing_case = db.query(Case).filter(Case.apk_hash == apk_hash).first()
    if existing_case:
        # Check if the APK file actually exists in the case directory, if not re-save it
        case_dir = os.path.join(DATA_DIR, str(existing_case.id))
        apk_path = os.path.join(case_dir, existing_case.apk_name)
        if not os.path.exists(apk_path):
            os.makedirs(case_dir, exist_ok=True)
            temp_path = os.path.join(DATA_DIR, "temp", file.filename)
            if save_upload_file(file, temp_path):
                if is_bundle:
                    bundle_path = os.path.join(case_dir, file.filename)
                    shutil.move(temp_path, bundle_path)
                    try:
                        extract_bundle(bundle_path, case_dir)
                    except Exception as e:
                        logger.error(f"Re-extracting bundle failed: {e}")
                else:
                    shutil.move(temp_path, apk_path)

        # If case exists but analysis is not completed (e.g. was interrupted, failed, or stuck), re-trigger
        if existing_case.status != "completed":
            existing_case.status = "analyzing"
            db.commit()
            thread = threading.Thread(
                target=_run_analysis_sync,
                args=(str(existing_case.id), existing_case.apk_name, apk_hash),
                daemon=True
            )
            thread.start()
        return existing_case

    # 2. Store temporarily to validate ZIP structure
    temp_path = os.path.join(DATA_DIR, "temp", file.filename)
    if not save_upload_file(file, temp_path):
        raise HTTPException(status_code=500, detail="Failed to save uploaded file temporarily.")
        
    if is_bundle:
        if not is_valid_bundle(temp_path):
            os.remove(temp_path)
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid split-APK bundle. No APK files found.")
    elif not is_valid_apk(temp_path):
        os.remove(temp_path)
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid APK structure. Missing AndroidManifest.xml.")

    # 3. Create new case in database
    case_number = f"CASE-{uuid.uuid4().hex[:8].upper()}"
    new_case = Case(
        case_number=case_number,
        apk_hash=apk_hash,
        apk_name=file.filename,
        status="analyzing",
        created_by=current_user.id
    )
    
    db.add(new_case)
    db.commit()
    db.refresh(new_case)
    
    # 4. Move file to permanent secure storage
    case_dir = os.path.join(DATA_DIR, str(new_case.id))
    os.makedirs(case_dir, exist_ok=True)
    permanent_path = os.path.join(case_dir, file.filename)
    shutil.move(temp_path, permanent_path)

    # 4b. Split-APK bundle: extract to <case_dir>/bundle/. The case keeps the original
    # bundle filename for display; resolve_analysis_apk() maps it to the base APK.
    bundle_info = None
    if is_bundle:
        try:
            bundle_info = extract_bundle(permanent_path, case_dir)
        except Exception as e:
            db.delete(new_case)
            db.commit()
            shutil.rmtree(case_dir, ignore_errors=True)
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Invalid split-APK bundle: {e}")
        if bundle_info.get("package_name"):
            new_case.package_name = bundle_info["package_name"]
        db.commit()
        db.refresh(new_case)

    # 5. Build sha256 manifest
    append_to_manifest(case_dir, file.filename, apk_hash)
    
    # 6. Log the upload action
    log_action(
        db=db,
        action="APK_UPLOADED",
        case_id=new_case.id,
        user_id=current_user.id,
        details={"filename": file.filename, "hash": apk_hash,
                 **({"bundle": bundle_info} if bundle_info else {})}
    )
    
    # 7. Run analysis in a background thread (no Redis/Celery needed)
    thread = threading.Thread(
        target=_run_analysis_sync,
        args=(str(new_case.id), file.filename, apk_hash),
        daemon=True
    )
    thread.start()
    
    return new_case
