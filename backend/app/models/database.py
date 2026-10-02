from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON, Enum as SQLEnum
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.sql import func
import uuid
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime
from app.models.enums import Role

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    role = Column(SQLEnum(Role), default=Role.INVESTIGATOR, nullable=False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    cases = relationship("Case", back_populates="creator")
    audit_logs = relationship("AuditLog", back_populates="user")

class Case(Base):
    __tablename__ = "cases"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_number = Column(String(50), unique=True, nullable=False)
    apk_hash = Column(String(64), nullable=False)
    apk_name = Column(String, nullable=False)
    package_name = Column(String, nullable=True)
    status = Column(String, default="pending")
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    creator = relationship("User", back_populates="cases")
    phase_results = relationship("PhaseResult", back_populates="case")
    audit_logs = relationship("AuditLog", back_populates="case")
    evidence_records = relationship("EvidenceRecord", back_populates="case")

class PhaseResult(Base):
    __tablename__ = "phase_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("cases.id"))
    phase = Column(String(50), nullable=False)
    result = Column(JSON)
    risk_score = Column(Integer)
    completed_at = Column(DateTime(timezone=True))

    case = relationship("Case", back_populates="phase_results")

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(UUID(as_uuid=True), ForeignKey("cases.id"), nullable=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String, nullable=False)
    details = Column(JSON, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    ip_address = Column(String, nullable=True)

    case = relationship("Case", back_populates="audit_logs")
    user = relationship("User", back_populates="audit_logs")

class EvidenceRecord(Base):
    __tablename__ = "evidence_records"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("cases.id"))
    artifact_type = Column(String(50))
    file_hash = Column(String(64), nullable=False)
    file_path = Column(String(500))
    collected_at = Column(DateTime(timezone=True), server_default=func.now())

    case = relationship("Case", back_populates="evidence_records")

class ApkFingerprint(Base):
    __tablename__ = "apk_fingerprints"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("cases.id"))
    fingerprint_id = Column(String(64), index=True)
    permission_set_hash = Column(String(64))
    class_shape_hash = Column(String(64))
    resource_hashes = Column(JSON)
    api_call_signature = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)

class Batch(Base):
    __tablename__ = "batches"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_by = Column(Integer, ForeignKey("users.id"))
    total_files = Column(Integer)
    created_at = Column(DateTime, default=datetime.utcnow)

class BatchCase(Base):
    __tablename__ = "batch_cases"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    batch_id = Column(UUID(as_uuid=True), ForeignKey("batches.id"))
    case_id = Column(UUID(as_uuid=True), ForeignKey("cases.id"))
