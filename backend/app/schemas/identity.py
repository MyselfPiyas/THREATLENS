from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.scanners.url_validation import UnsafeTarget, normalize_url


class IdentityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(min_length=1, max_length=8192)
    claimed_brand: str | None = Field(default=None, max_length=80)
    scan_id: UUID | None = None

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        try:
            return normalize_url(value)
        except UnsafeTarget as error:
            raise ValueError(str(error)) from error


class IdentityResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scan_id: UUID | None = None
    claimed_brand: str | None
    actual_domain: str
    similarity_score: float = Field(ge=0, le=1)
    suspicious_characters: list[str]
    detection_category: str
    evidence: list[str]
    confidence: float = Field(ge=0, le=1)
    explanation: str
    brand_domain: str | None = None


class BrandReference(BaseModel):
    id: str
    name: str
    domains: list[str]
