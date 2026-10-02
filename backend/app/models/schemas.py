from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from uuid import UUID

# Shared properties
class CaseBase(BaseModel):
    case_number: str
    apk_hash: str
    apk_name: Optional[str] = None
    package_name: Optional[str] = None
    status: Optional[str] = "pending"
    threat_score: Optional[int] = 0

# Properties to receive on case creation
class CaseCreate(CaseBase):
    pass

# Properties to receive on case update
class CaseUpdate(BaseModel):
    status: Optional[str] = None
    apk_name: Optional[str] = None

# Properties shared by models stored in DB
class CaseInDBBase(CaseBase):
    id: UUID
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

# Properties to return to client
class Case(CaseInDBBase):
    pass

# --- User Schemas ---
from app.models.enums import Role

class UserBase(BaseModel):
    username: str
    role: Role = Role.INVESTIGATOR

class UserCreate(UserBase):
    password: str

from pydantic import field_validator

class UserSignup(UserCreate):
    @field_validator("username")
    @classmethod
    def validate_username(cls, v):
        if not v.endswith("@cyber.gov"):
            raise ValueError("Email must end with @cyber.gov")
        return v

class UserResponse(UserBase):
    id: int
    created_at: datetime

    model_config = {"from_attributes": True}

# --- Token Schemas ---
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

