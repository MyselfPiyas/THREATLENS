from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.scanners.url_validation import UnsafeTarget, normalize_url


class TlsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(min_length=1, max_length=8192)
    scan_id: UUID | None = None

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        try:
            return normalize_url(value)
        except UnsafeTarget as error:
            raise ValueError(str(error)) from error


class SecurityHeadersRequest(TlsRequest):
    pass


class TlsResult(BaseModel):
    model_config = ConfigDict(extra="allow")
    scan_id: UUID | None = None
    url: str
    available: bool
    certificate: dict[str, Any] | None = None
    reason: str | None = None
    limitations: list[str] = []


class TlsStoredResult(BaseModel):
    scan_id: UUID
    tls: dict[str, Any] | None = None
    security_headers: dict[str, Any] | None = None
