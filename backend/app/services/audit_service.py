import json
import os
from sqlalchemy.orm import Session
from app.models.database import AuditLog
from typing import Optional
import uuid

def log_action(db: Session, action: str, case_id: Optional[uuid.UUID] = None, user_id: Optional[int] = None, details: dict = None, ip_address: str = None) -> AuditLog:
    """
    Records an action in the database audit log.
    """
    log_entry = AuditLog(
        case_id=case_id,
        user_id=user_id,
        action=action,
        details=details or {},
        ip_address=ip_address
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)
    return log_entry

def export_chain_of_custody(db: Session, case_id: uuid.UUID, output_dir: str) -> str:
    """
    Exports the chain of custody for a case as a JSON file.
    Returns the path to the exported JSON file.
    """
    logs = db.query(AuditLog).filter(AuditLog.case_id == case_id).order_by(AuditLog.timestamp).all()
    
    chain_data = {
        "case_id": str(case_id),
        "chain_of_custody": []
    }
    
    for log in logs:
        user_name = log.user.username if log.user else "System"
        chain_data["chain_of_custody"].append({
            "timestamp": log.timestamp.isoformat(),
            "actor": user_name,
            "action": log.action,
            "details": log.details,
            "ip_address": log.ip_address
        })
        
    os.makedirs(output_dir, exist_ok=True)
    export_path = os.path.join(output_dir, "chain_of_custody.json")
    
    with open(export_path, "w") as f:
        json.dump(chain_data, f, indent=4)
        
    return export_path
