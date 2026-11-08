from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class Indicator(BaseModel):
    id: UUID
    indicator_type: str
    indicator_value: str
    source: str
    threat_category: str
    confidence: float = Field(ge=0, le=1)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class IndicatorPage(BaseModel):
    items: list[Indicator]
    page: int
    page_size: int
    total: int | None = None


class Relationship(BaseModel):
    id: UUID | None = None
    source_scan_id: UUID
    related_scan_id: UUID
    relationship_type: str
    confidence: float = Field(ge=0, le=1)
    evidence: dict[str, Any] = Field(default_factory=dict)


class GraphNode(BaseModel):
    id: str
    node_type: str
    label: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    relationship_type: str
    confidence: float = Field(ge=0, le=1)
    evidence: dict[str, Any] = Field(default_factory=dict)


class ScamDnaGraph(BaseModel):
    scan_id: UUID
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    relationships: list[Relationship]
    deterministic_summary: str
    ai_interpretation: dict[str, Any] | None = None


class CorrelateRequest(BaseModel):
    scan_id: UUID
    related_scan_ids: list[UUID] = Field(default_factory=list, max_length=50)


class DnaSummary(BaseModel):
    scan_id: UUID
    relationship_count: int
    indicator_count: int
    confidence: float | None = None
    summary: str
    ai_interpretation: dict[str, Any] | None = None


class Campaign(BaseModel):
    id: str
    name: str
    scan_ids: list[UUID]
    relationship_count: int
    confidence: float
    evidence: list[dict[str, Any]]
