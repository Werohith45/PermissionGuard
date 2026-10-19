from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

class Token(BaseModel):
    access_token: str
    token_type: str
    user: Dict[str, Any]

class LoginRequest(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    full_name: str
    role_id: str
    role_name: str
    department_id: str
    department_name: str
    status: str
    created_at: str

class ResourceCreate(BaseModel):
    name: str
    type: str
    department_id: str
    owner_id: str
    sensitivity: str

class ResourceUpdate(BaseModel):
    name: Optional[str] = None
    type: Optional[str] = None
    department_id: Optional[str] = None
    sensitivity: Optional[str] = None
    status: Optional[str] = None
    change_summary: Optional[str] = "Resource metadata updated"

class PermissionRequestCreate(BaseModel):
    resource_id: str
    permission_type: str # READ, WRITE, EDIT, DOWNLOAD, SHARE
    duration_days: int = Field(ge=1, le=365)
    reason: str = Field(min_length=5)

class RequestReview(BaseModel):
    status: str # APPROVED, REJECTED, MORE_INFO_REQUESTED
    comments: Optional[str] = None

class PermissionRevalidate(BaseModel):
    reason: str = Field(min_length=5)

class PermissionExtend(BaseModel):
    additional_days: int = Field(ge=1, le=180)
    reason: str = Field(min_length=5)

class FindingResolution(BaseModel):
    action: str # REVALIDATE, REVOKE, DISMISS
    notes: Optional[str] = None
    reason: Optional[str] = None

class SystemSettingsUpdate(BaseModel):
    inactivity_threshold_days: int
    default_permission_days: int
    expiring_soon_days: int
    low_risk_threshold: int
    medium_risk_threshold: int
    high_risk_threshold: int
    critical_risk_threshold: int

class SimulateActivityRequest(BaseModel):
    resource_id: str
    action: str = "READ" # OPEN, READ, EDIT, DOWNLOAD, SHARE
