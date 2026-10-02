"""
Runs emulator-based dynamic analysis for a case and refreshes the phases
that depend on it (C2 intelligence, vulnerability scan).
"""

import os
import uuid as _uuid
import logging
import threading
from datetime import datetime

logger = logging.getLogger(__name__)

from app.config import settings as _settings
DATA_DIR = _settings.CASES_DIR
DYNAMIC_DURATION = int(os.environ.get("APEX_DYNAMIC_DURATION", "90"))

_running: set = set()
_running_lock = threading.Lock()


def _parse_dt(val):
    if isinstance(val, str):
        try:
            return datetime.fromisoformat(val.replace("Z", "+00:00")).replace(tzinfo=None)
        except Exception:
            pass
    return val if isinstance(val, datetime) else datetime.utcnow()


def _replace_phase(db, case_uuid, phase: str, result: dict) -> None:
    from app.models.database import PhaseResult
    for old in db.query(PhaseResult).filter(PhaseResult.case_id == case_uuid, PhaseResult.phase == phase).all():
        db.delete(old)
    db.add(PhaseResult(
        case_id=case_uuid, phase=phase, result=result,
        risk_score=result.get("risk_score", 0) or 0,
        completed_at=_parse_dt(result.get("completed_at")),
    ))
    db.commit()


def is_running(case_id: str) -> bool:
    return str(case_id) in _running


def run_dynamic_for_case(case_id: str, apk_name: str, duration: int = DYNAMIC_DURATION) -> None:
    """Blocking. Safe to call from a background thread."""
    from app.models.session import SessionLocal
    from app.engines.dynamic import run_full_dynamic_analysis

    cid = str(case_id)
    with _running_lock:
        if cid in _running:
            logger.info(f"Dynamic analysis already running for {cid}")
            return
        _running.add(cid)

    db = SessionLocal()
    case_uuid = _uuid.UUID(cid)
    case_dir = os.path.join(DATA_DIR, cid)
    from app.utils.file_utils import resolve_analysis_apk
    apk_path = resolve_analysis_apk(case_dir, apk_name)
    try:
        _replace_phase(db, case_uuid, "dynamic", {
            "status": "running", "mode": "emulator",
            "message": "Booting emulator and executing the app", "started_at": datetime.utcnow().isoformat(),
        })
        result = run_full_dynamic_analysis(apk_path, case_dir, duration=duration, force_emulator=True)
        _replace_phase(db, case_uuid, "dynamic", result)

        try:
            from app.engines.c2 import run_full_c2_intelligence
            _replace_phase(db, case_uuid, "c2_intelligence", run_full_c2_intelligence(apk_path, case_dir, cid))
        except Exception as e:
            logger.warning(f"C2 refresh after dynamic failed: {e}")
        try:
            from app.engines.vulnerability import run_vulnerability_scan
            _replace_phase(db, case_uuid, "vulnerability", run_vulnerability_scan(case_dir, cid))
        except Exception as e:
            logger.warning(f"Vulnerability refresh after dynamic failed: {e}")
        logger.info(f"Dynamic analysis + correlation complete for {cid} (mode={result.get('mode')})")
    except Exception as e:
        logger.exception(f"Dynamic analysis failed for {cid}: {e}")
        try:
            _replace_phase(db, case_uuid, "dynamic", {"status": "failed", "errors": [str(e)],
                                                      "completed_at": datetime.utcnow().isoformat()})
        except Exception:
            pass
    finally:
        db.close()
        with _running_lock:
            _running.discard(cid)


def start_dynamic_in_background(case_id: str, apk_name: str, duration: int = DYNAMIC_DURATION) -> bool:
    if is_running(case_id):
        return False
    threading.Thread(target=run_dynamic_for_case, args=(str(case_id), apk_name, duration), daemon=True).start()
    return True
