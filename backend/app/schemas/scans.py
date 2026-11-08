from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.scanners.url_validation import UnsafeTarget, normalize_url


class UrlScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(min_length=1, max_length=8192)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        try:
            return normalize_url(value)
        except UnsafeTarget as error:
            raise ValueError(str(error)) from error


class ScanAccepted(BaseModel):
    scan_id: UUID
    status: Literal["queued"]
    status_url: str


class ScanRecord(BaseModel):
    id: UUID
    user_id: UUID
    scan_type: str
    target: str
    normalized_target: str
    status: str
    risk_level: str
    risk_score: int
    summary: str
    started_at: datetime
    completed_at: datetime | None = None
    created_at: datetime


class ScanStatus(BaseModel):
    scan_id: UUID
    status: str
    risk_level: str
    risk_score: int
    summary: str


class ScanFinding(BaseModel):
    id: UUID
    scan_id: UUID
    category: str
    title: str
    description: str
    severity: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    source: str
    confidence: float
    created_at: datetime


class ScanEvent(BaseModel):
    id: UUID
    scan_id: UUID
    event_type: str
    title: str
    description: str
    event_data: dict[str, Any] = Field(default_factory=dict)
    occurred_at: datetime


class ScanReport(BaseModel):
    scan: ScanRecord
    findings: list[ScanFinding]
    events: list[ScanEvent]
