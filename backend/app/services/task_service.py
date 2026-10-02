from celery import Celery
from app.config import settings
import os
from datetime import datetime
from app.models.session import SessionLocal
from app.models.database import Case, PhaseResult

celery_app = Celery(
    "apex_x_tasks",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)

@celery_app.task(name="analyze_apk_task")
def analyze_apk_task(case_id: str, run_static: bool = True, run_dynamic: bool = True):
    """
    Background task to orchestrate analysis phases.
    Executes Static and Dynamic analysis engines and stores results in the database.
    """
    from app.engines.static import run_full_static_analysis
    from app.engines.dynamic import run_full_dynamic_analysis
    from app.services.hash_service import calculate_sha256, append_to_manifest
    import logging

    logger = logging.getLogger(__name__)
    logger.info(f"Starting analysis for Case ID: {case_id}")
    
    db = SessionLocal()
    try:
        case = db.query(Case).filter(Case.id == case_id).first()
        if not case:
            logger.error(f"Case {case_id} not found")
            return {"error": "case_not_found"}
            
        case.status = "running"
        db.commit()
        
        # Determine paths
        from app.config import settings as _s
        DATA_DIR = _s.CASES_DIR
        case_dir = os.path.join(DATA_DIR, str(case_id))
        from app.utils.file_utils import resolve_analysis_apk
        apk_path = resolve_analysis_apk(case_dir, case.apk_name)
        
        def hash_and_log(file_path: str, artifact_name: str):
            if os.path.exists(file_path):
                with open(file_path, "rb") as f:
                    file_hash = calculate_sha256(f)
                append_to_manifest(case_dir, artifact_name, file_hash)
                
        if not os.path.exists(apk_path):
            case.status = "failed"
            db.commit()
            logger.error(f"APK file not found for case {case_id}: {apk_path}")
            return {"error": "apk_not_found"}

        # 1. Static Analysis Phase
        if run_static:
            logger.info(f"Running Static Analysis for {case_id}")
            static_result = run_full_static_analysis(apk_path, case_dir)
            
            # Save static phase result
            phase_record = PhaseResult(
                case_id=case_id,
                phase="static",
                result=static_result,
                risk_score=static_result.get("risk_score", 0),
                completed_at=static_result.get("completed_at")
            )
            db.add(phase_record)
            
            # Save fingerprint to DB
            fp_data = static_result.get("steps", {}).get("fingerprint", {}).get("data", {})
            if fp_data and fp_data.get("fingerprint_id"):
                from app.models.database import ApkFingerprint
                fp_record = ApkFingerprint(
                    case_id=case_id,
                    fingerprint_id=fp_data.get("fingerprint_id"),
                    permission_set_hash=fp_data.get("permission_set_hash"),
                    class_shape_hash=fp_data.get("class_shape_hash"),
                    resource_hashes=fp_data.get("resource_hashes", {}),
                    api_call_signature=fp_data.get("api_call_signature", [])
                )
                db.add(fp_record)

            db.commit()
            
            hash_and_log(os.path.join(case_dir, "static_analysis", "static_report.json"), "static_report.json")
            logger.info(f"Static Analysis completed for {case_id} with score {phase_record.risk_score}")

        # 2. Dynamic Analysis Phase
        if run_dynamic:
            logger.info(f"Running Dynamic Analysis for {case_id}")
            dynamic_result = run_full_dynamic_analysis(apk_path, case_dir, duration=60)
            
            # Save dynamic phase result
            phase_record = PhaseResult(
                case_id=case_id,
                phase="dynamic",
                result=dynamic_result,
                risk_score=dynamic_result.get("risk_score", 0),
                completed_at=dynamic_result.get("completed_at")
            )
            db.add(phase_record)
            db.commit()
            
            hash_and_log(os.path.join(case_dir, "dynamic_analysis", "dynamic_report.json"), "dynamic_report.json")
            logger.info(f"Dynamic Analysis completed for {case_id} with score {phase_record.risk_score}")

        # TM3 INTELLIGENCE LAYER PHASES --------------------------------------
        
        # 3. C2 Intelligence Phase
        from app.engines.c2 import run_full_c2_intelligence
        logger.info(f"Running C2 Intelligence for {case_id}")
        c2_result = run_full_c2_intelligence(apk_path, case_dir, str(case_id))
        
        phase_record = PhaseResult(
            case_id=case_id,
            phase="c2_intelligence",
            result=c2_result,
            risk_score=c2_result.get("risk_score", 0),
            completed_at=c2_result.get("completed_at")
        )
        db.add(phase_record)
        db.commit()
        
        # 3.5 Cross-Case Syndicate Correlation
        from app.engines.c2 import correlation_engine
        logger.info(f"Running Cross-Case Syndicate Correlation for {case_id}")
        correlation_result = correlation_engine.find_correlated_cases(str(case_id), case.apk_hash)
        
        phase_record = PhaseResult(
            case_id=case_id,
            phase="correlation",
            result=correlation_result,
            risk_score=0,
            completed_at=datetime.utcnow()
        )
        db.add(phase_record)
        db.commit()

        # 4. Vulnerability Discovery Phase
        from app.engines.vulnerability import run_vulnerability_scan
        logger.info(f"Running Vulnerability Discovery for {case_id}")
        vuln_result = run_vulnerability_scan(case_dir, str(case_id))
        
        phase_record = PhaseResult(
            case_id=case_id,
            phase="vulnerability",
            result=vuln_result,
            risk_score=vuln_result.get("risk_score", 0),
            completed_at=vuln_result.get("completed_at")
        )
        db.add(phase_record)
        db.commit()
        
        hash_and_log(os.path.join(case_dir, "vulnerability_analysis", "vulnerability_report.json"), "vulnerability_report.json")

        # 5. Threat Reasoning (LLM Narrative)
        from app.engines.intelligence import threat_reasoner
        logger.info(f"Running Threat Reasoning Agent for {case_id}")
        narrative_result = threat_reasoner.generate_threat_narrative(case_dir)
        
        # Save narrative to file so it can be indexed
        narrative_dir = os.path.join(case_dir, "intelligence_analysis")
        os.makedirs(narrative_dir, exist_ok=True)
        with open(os.path.join(narrative_dir, "threat_narrative.json"), "w") as f:
            import json
            json.dump(narrative_result, f, indent=2)

        phase_record = PhaseResult(
            case_id=case_id,
            phase="threat_reasoning",
            result=narrative_result,
            risk_score=0,
            completed_at=None
        )
        db.add(phase_record)
        db.commit()
        
        hash_and_log(os.path.join(narrative_dir, "threat_narrative.json"), "threat_narrative.json")

        # 6. Malware Family Classification
        from app.engines.intelligence import malware_classifier
        logger.info(f"Running Malware Family Classification for {case_id}")
        classification_result = malware_classifier.classify_malware(case_dir)

        phase_record = PhaseResult(
            case_id=case_id,
            phase="malware_classification",
            result=classification_result,
            risk_score=0,
            completed_at=None
        )
        db.add(phase_record)
        db.commit()

        hash_and_log(os.path.join(case_dir, "intelligence_analysis", "malware_classification.json"), "malware_classification.json")

        # 7. Co-Pilot RAG Indexing
        from app.engines.intelligence import copilot_rag
        logger.info(f"Indexing artifacts for Officer Co-Pilot: Case {case_id}")
        copilot_rag.index_case_artifacts(str(case_id), case_dir)

        # 8. Pre-generate English Report
        from app.api.routes.reports import _load_case_data, _generate_report_narrative
        logger.info(f"Pre-generating English forensic report for {case_id}")
        case_data_report = _load_case_data(str(case_id), db)
        english_report = _generate_report_narrative(case_data_report)
        
        report_record = PhaseResult(
            case_id=case_id,
            phase="report_english",
            result={"narrative": english_report},
            risk_score=0,
            completed_at=None
        )
        db.add(report_record)
        db.commit()

        # ---------------------------------------------------------------------

        # Complete Case
        case.status = "completed"
        db.commit()
        logger.info(f"Successfully completed all analysis for Case ID: {case_id}")
        return {"case_id": case_id, "status": "completed"}
        
    except Exception as e:
        logger.error(f"Analysis task failed for case {case_id}: {e}")
        db.rollback()
        
        case = db.query(Case).filter(Case.id == case_id).first()
        if case:
            case.status = "failed"
            db.commit()
            
        return {"case_id": case_id, "status": "failed", "error": str(e)}
    finally:
        db.close()
