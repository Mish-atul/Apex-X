from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.api import dependencies
from app.api.middleware.rbac import get_current_user
from app.models.database import Case, User, PhaseResult
from app.services.task_service import analyze_apk_task
from app.services.audit_service import log_action
import logging

router = APIRouter()
logger = logging.getLogger(__name__)

@router.post("/{case_id}/static", status_code=status.HTTP_202_ACCEPTED)
async def trigger_static_analysis(
    case_id: str,
    db: Session = Depends(dependencies.get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Manually trigger static analysis for a case.
    """
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    # Trigger background task for static only
    analyze_apk_task.delay(case_id, run_static=True, run_dynamic=False)
    
    log_action(
        db=db,
        action="STATIC_ANALYSIS_TRIGGERED",
        case_id=case.id,
        user_id=current_user.id,
        details={"case_number": case.case_number}
    )
    
    return {"message": "Static analysis task queued", "case_id": case_id}

@router.post("/{case_id}/dynamic", status_code=status.HTTP_202_ACCEPTED)
async def trigger_dynamic_analysis(
    case_id: str,
    db: Session = Depends(dependencies.get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Manually trigger dynamic analysis for a case.
    """
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    # Trigger background task for dynamic only
    analyze_apk_task.delay(case_id, run_static=False, run_dynamic=True)
    
    log_action(
        db=db,
        action="DYNAMIC_ANALYSIS_TRIGGERED",
        case_id=case.id,
        user_id=current_user.id,
        details={"case_number": case.case_number}
    )
    
    return {"message": "Dynamic analysis task queued", "case_id": case_id}

@router.post("/{case_id}/full", status_code=status.HTTP_202_ACCEPTED)
async def trigger_full_analysis(
    case_id: str,
    db: Session = Depends(dependencies.get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Manually trigger both static and dynamic analysis for a case.
    """
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    # Trigger full background task
    analyze_apk_task.delay(case_id, run_static=True, run_dynamic=True)
    
    log_action(
        db=db,
        action="FULL_ANALYSIS_TRIGGERED",
        case_id=case.id,
        user_id=current_user.id,
        details={"case_number": case.case_number}
    )
    
    return {"message": "Full analysis task queued", "case_id": case_id}

@router.get("/{case_id}/status")
async def get_analysis_status(
    case_id: str,
    db: Session = Depends(dependencies.get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get the status of analysis for a case.
    """
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    # Get phase results
    results = db.query(PhaseResult).filter(PhaseResult.case_id == case_id).all()
    
    phases = {}
    for r in results:
        phases[r.phase] = {
            "completed_at": r.completed_at,
            "risk_score": r.risk_score
        }
        
    return {
        "case_id": case_id,
        "case_status": case.status,
        "phases_completed": list(phases.keys()),
        "details": phases
    }
