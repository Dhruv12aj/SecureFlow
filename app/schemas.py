from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Status(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"


class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=120)
    severity: Severity
    status: Status = Status.OPEN
    source: str = Field(min_length=2, max_length=80)
    description: str = Field(default="", max_length=2000)


class IncidentUpdate(BaseModel):
    # everything optional so an analyst can just move the status along
    title: Optional[str] = Field(default=None, min_length=3, max_length=120)
    severity: Optional[Severity] = None
    status: Optional[Status] = None
    source: Optional[str] = Field(default=None, min_length=2, max_length=80)
    description: Optional[str] = Field(default=None, max_length=2000)


class Incident(BaseModel):
    id: int
    title: str
    severity: Severity
    status: Status
    source: str
    description: str
    detected_by: str
    attacker_ip: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None
    # calculated, not stored
    sla_due_at: datetime
    is_overdue: bool
    risk_score: int
