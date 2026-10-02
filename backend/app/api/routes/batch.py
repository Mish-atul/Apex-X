from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, BackgroundTasks
from sqlalchemy.orm import Session
import zipfile
import tempfile
import os
import shutil
import hashlib

from app.api.dependencies import get_db
from app.models.database import Batch, BatchCase, Case
from app.services.task_service import analyze_apk_task

router = APIRouter()

@router.post("/upload")
async def upload_batch(background_tasks: BackgroundTasks, file: UploadFile = File(...), db: Session = Depends(get_db)):
    """
    Upload a ZIP file containing multiple APKs for bulk triage.
    """
    if not file.filename.endswith('.zip'):
        raise HTTPException(status_code=400, detail="Must be a ZIP file")
        
    # Create batch record
    batch = Batch(name=file.filename)
    db.add(batch)
    db.commit()
    db.refresh(batch)
    
    # Process zip
    temp_dir = tempfile.mkdtemp()
    zip_path = os.path.join(temp_dir, file.filename)
    
    try:
        with open(zip_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
            
        extracted_apks = []
        for root, _, files in os.walk(temp_dir):
            for f in files:
                if f.endswith('.apk'):
                    extracted_apks.append(os.path.join(root, f))
                    
        for apk_path in extracted_apks:
            # Hash APK
            with open(apk_path, "rb") as f:
                apk_hash = hashlib.sha256(f.read()).hexdigest()
                
            # Create Case
            apk_filename = os.path.basename(apk_path)
            case = Case(
                apk_hash=apk_hash,
                filename=apk_filename,
                status="pending"
            )
            db.add(case)
            db.commit()
            db.refresh(case)
            
            # Link to Batch
            batch_case = BatchCase(
                batch_id=batch.id,
                case_id=case.id,
                triage_score=0 # to be updated by lightweight triage if needed
            )
            db.add(batch_case)
            db.commit()
            
            # Enqueue task
            analyze_apk_task.delay(str(case.id), run_static=True, run_dynamic=True)
            
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Batch processing failed: {str(e)}")
        
    return {
        "status": "success",
        "batch_id": batch.id,
        "cases_queued": len(extracted_apks)
    }

@router.get("/{batch_id}")
def get_batch(batch_id: str, db: Session = Depends(get_db)):
    batch = db.query(Batch).filter(Batch.id == batch_id).first()
    if not batch:
        raise HTTPException(status_code=404, detail="Batch not found")
        
    cases = db.query(BatchCase).filter(BatchCase.batch_id == batch_id).all()
    return {
        "batch": batch,
        "cases": cases
    }
