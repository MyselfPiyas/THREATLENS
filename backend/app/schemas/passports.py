from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field


PassportStatus = Literal[
    "VERIFIED", "OFFCHAIN_VERIFIED", "INTEGRITY_MISMATCH", "NOT_FOUND",
    "INVALID_REPORT", "VERIFICATION_ERROR", "NOT_REGISTERED", "PENDING", "CONFIRMED", "FAILED",
]


class PassportCreateRequest(BaseModel):
    scan_id: UUID


class PassportRecord(BaseModel):
    id: UUID
    scan_id: UUID
    user_id: UUID
    report_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    report_version: str
    hash_algorithm: Literal["SHA-256"]
    verification_status: PassportStatus
    verification_at: datetime | None = None
    public_sharing_enabled: bool = False
    created_at: datetime
    updated_at: datetime | None = None


class PassportProof(PassportRecord):
    canonical_report: dict[str, Any]
    calculated_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    integrity_match: bool


class PassportVerifyResult(BaseModel):
    passport: PassportRecord
    calculated_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    integrity_match: bool
    verification_timestamp: datetime
    detail: str


class PassportUploadVerifyResult(BaseModel):
    passport_id: UUID
    report_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    calculated_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    integrity_match: bool
    verification_status: Literal["OFFCHAIN_VERIFIED", "INTEGRITY_MISMATCH"]
    verification_timestamp: datetime


class PublicSharingResult(BaseModel):
    passport_id: UUID
    public_token: str
    verification_status: PassportStatus
    enabled: bool = True


class PassportExplanation(BaseModel):
    passport_id: UUID
    generated_by: Literal["openrouter", "deterministic"]
    explanation: dict[str, Any]


class PublicPassportVerification(BaseModel):
    passport_id: UUID
    report_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    hash_algorithm: Literal["SHA-256"] = "SHA-256"
    report_version: str
    created_at: datetime
    verification_status: Literal["OFFCHAIN_VERIFIED", "INTEGRITY_MISMATCH", "INVALID_REPORT"]
    integrity_match: bool
    detail: str
