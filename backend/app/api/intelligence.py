from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.dependencies import get_current_principal
from app.schemas.intelligence import Campaign, CorrelateRequest, DnaSummary, Indicator, IndicatorPage, ScamDnaGraph
from app.services.auth import AuthenticatedPrincipal
from app.services.scam_dna_ai_service import interpret_scam_dna
from app.services.scan_store import ScanStore
from app.services.threat_correlation_service import ThreatCorrelationService
from app.services.threat_intelligence_service import ThreatIntelligenceService

router = APIRouter(tags=["threat intelligence"])


@router.get("/intelligence/overview")
async def intelligence_overview(principal: AuthenticatedPrincipal = Depends(get_current_principal)) -> dict:
    return await ThreatIntelligenceService().overview()


@router.post("/intelligence/refresh")
async def refresh_intelligence(principal: AuthenticatedPrincipal = Depends(get_current_principal)) -> dict:
    try:
        result = await ThreatIntelligenceService().refresh_openphish()
    except RuntimeError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    return result


@router.get("/intelligence/indicators", response_model=IndicatorPage)
async def intelligence_indicators(page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100), search: str | None = Query(None, max_length=120), indicator_type: str | None = Query(None), principal: AuthenticatedPrincipal = Depends(get_current_principal)) -> IndicatorPage:
    rows = await ThreatIntelligenceService().list_indicators(page, page_size, search, indicator_type)
    return IndicatorPage(items=[Indicator.model_validate(row) for row in rows], page=page, page_size=page_size)


@router.get("/intelligence/indicators/{indicator_id}", response_model=Indicator)
async def intelligence_indicator(indicator_id: UUID, principal: AuthenticatedPrincipal = Depends(get_current_principal)) -> Indicator:
    rows = await ThreatIntelligenceService().store.admin_rows("threat_indicators", {"select": "id,indicator_type,indicator_value,source,threat_category,confidence,first_seen,last_seen,metadata", "id": f"eq.{indicator_id}", "limit": "1"})
    if not rows:
        raise HTTPException(status_code=404, detail="Threat indicator not found.")
    return Indicator.model_validate(rows[0])


@router.get("/intelligence/campaigns", response_model=list[Campaign])
async def intelligence_campaigns(principal: AuthenticatedPrincipal = Depends(get_current_principal)) -> list[Campaign]:
    return []


@router.get("/intelligence/campaigns/{campaign_id}", response_model=Campaign)
async def intelligence_campaign(campaign_id: str, principal: AuthenticatedPrincipal = Depends(get_current_principal)) -> Campaign:
    raise HTTPException(status_code=404, detail="Campaign not found. Campaigns are derived only from evidence-backed relationships.")


async def _graph(scan_id: UUID, principal: AuthenticatedPrincipal) -> ScamDnaGraph:
    try:
        return await ThreatCorrelationService().correlate(scan_id, principal)
    except LookupError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error


@router.get("/scam-dna/{scan_id}", response_model=ScamDnaGraph)
async def scam_dna(scan_id: UUID, principal: AuthenticatedPrincipal = Depends(get_current_principal)) -> ScamDnaGraph:
    return await _graph(scan_id, principal)


@router.post("/scam-dna/correlate", response_model=ScamDnaGraph)
async def correlate(request: CorrelateRequest, principal: AuthenticatedPrincipal = Depends(get_current_principal)) -> ScamDnaGraph:
    try:
        return await ThreatCorrelationService().correlate(request.scan_id, principal, request.related_scan_ids)
    except LookupError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error


@router.get("/scam-dna/{scan_id}/relationships")
async def scam_relationships(scan_id: UUID, principal: AuthenticatedPrincipal = Depends(get_current_principal)) -> list[dict]:
    await _graph(scan_id, principal)
    return await ScanStore().read_own_relationships(scan_id, principal)


@router.get("/scam-dna/{scan_id}/summary", response_model=DnaSummary)
async def scam_summary(scan_id: UUID, principal: AuthenticatedPrincipal = Depends(get_current_principal)) -> DnaSummary:
    graph = await _graph(scan_id, principal)
    confidences = [edge.confidence for edge in graph.edges]
    return DnaSummary(scan_id=scan_id, relationship_count=len(graph.relationships), indicator_count=sum(1 for node in graph.nodes if node.node_type != "scan"), confidence=max(confidences) if confidences else None, summary=graph.deterministic_summary)


@router.post("/scam-dna/{scan_id}/analyze", response_model=ScamDnaGraph)
async def analyze_scam_dna(scan_id: UUID, principal: AuthenticatedPrincipal = Depends(get_current_principal)) -> ScamDnaGraph:
    graph = await _graph(scan_id, principal)
    evidence = [{"id": edge.id, "type": edge.relationship_type, "source": "deterministic_correlation", "confidence": edge.confidence, "evidence": edge.evidence} for edge in graph.edges]
    graph.ai_interpretation = await interpret_scam_dna(scan_id, evidence)
    return graph
