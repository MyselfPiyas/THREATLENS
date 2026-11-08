from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class MessageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    content: str = Field(min_length=1, max_length=20000)
    allow_llm: bool = False

    @field_validator("content")
    @classmethod
    def non_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Message content must not be blank.")
        return value


class MessageResult(BaseModel):
    analysis_id: UUID
    risk_level: str
    risk_score: int = Field(ge=0, le=100)
    detected_tactics: list[str]
    highlighted_phrases: list[str]
    extracted_indicators: dict[str, list[str]]
    evidence: list[str]
    explanation: str
    recommended_actions: list[str]
    source: str = "threatlens_rules"


class QrResult(BaseModel):
    analysis_id: UUID
    decoded: bool
    content_type: str
    extracted_content: str | None = None
    url_scan_id: UUID | None = None
    risk_level: str | None = None
    risk_score: int | None = Field(default=None, ge=0, le=100)
    evidence: list[str]
    explanation: str


class StoredAnalysis(BaseModel):
    model_config = ConfigDict(extra="ignore")
    analysis_id: UUID
    result: dict[str, Any]
