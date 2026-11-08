from __future__ import annotations

from collections import defaultdict
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from app.schemas.intelligence import GraphEdge, GraphNode, Relationship, ScamDnaGraph
from app.services.auth import AuthenticatedPrincipal
from app.services.scan_store import ScanStore
from app.services.threat_intelligence_service import ThreatIntelligenceService


class ThreatCorrelationService:
    def __init__(self, store: ScanStore | None = None) -> None:
        self.store = store or ScanStore()
        self.intelligence = ThreatIntelligenceService(self.store)

    @staticmethod
    def _domain(target: str) -> str:
        return (urlsplit(target).hostname or "").casefold()

    async def correlate(self, scan_id: UUID, principal: AuthenticatedPrincipal, related_ids: list[UUID] | None = None) -> ScamDnaGraph:
        scans = await self.store.read_own_rows(principal, "scans", {"select": "id,target,normalized_target,scan_type,status,risk_level,risk_score", "user_id": f"eq.{principal.user_id}", "order": "created_at.desc", "limit": "100"})
        selected = next((row for row in scans if str(row.get("id")) == str(scan_id)), None)
        if not selected:
            raise LookupError("Scan not found.")
        candidates = [row for row in scans if row is not selected and (not related_ids or UUID(str(row["id"])) in related_ids)]
        relationships: list[Relationship] = []
        related_indicators = await self.intelligence.related_indicators(selected)
        for other in candidates:
            source_domain = self._domain(str(selected.get("normalized_target", "")))
            other_domain = self._domain(str(other.get("normalized_target", "")))
            if source_domain and source_domain == other_domain:
                evidence = {"signal": "exact_registrable_domain", "source": "scan_targets", "explanation": "Both investigations use the same hostname; this is shared targeting evidence, not proof of a campaign."}
                relationship = Relationship(source_scan_id=scan_id, related_scan_id=UUID(str(other["id"])), relationship_type="shared_domain", confidence=0.75, evidence=evidence)
                await self.store.upsert_relationship(relationship.model_dump(mode="json"))
                relationships.append(relationship)
        nodes = [GraphNode(id=f"scan:{scan_id}", node_type="scan", label=str(selected.get("target", scan_id)), metadata={"risk_level": selected.get("risk_level"), "risk_score": selected.get("risk_score")})]
        edges: list[GraphEdge] = []
        for relationship in relationships:
            other = next((x for x in candidates if str(x.get("id")) == str(relationship.related_scan_id)), {})
            nodes.append(GraphNode(id=f"scan:{relationship.related_scan_id}", node_type="scan", label=str(other.get("target", relationship.related_scan_id)), metadata={"risk_level": other.get("risk_level"), "risk_score": other.get("risk_score")}))
            edges.append(GraphEdge(id=f"relationship:{relationship.related_scan_id}", source=f"scan:{scan_id}", target=f"scan:{relationship.related_scan_id}", relationship_type=relationship.relationship_type, confidence=relationship.confidence, evidence=relationship.evidence))
        for indicator in related_indicators:
            node_id = f"indicator:{indicator.get('id')}"
            nodes.append(GraphNode(id=node_id, node_type=str(indicator.get("indicator_type", "indicator")), label=str(indicator.get("indicator_value", "")), metadata={"source": indicator.get("source"), "confidence": indicator.get("confidence")}))
            edges.append(GraphEdge(id=f"indicator-edge:{indicator.get('id')}", source=f"scan:{scan_id}", target=node_id, relationship_type="threat_indicator_match", confidence=float(indicator.get("confidence", 0)), evidence={"source": indicator.get("source"), "indicator_id": indicator.get("id")}))
        summary = "No evidence-backed relationships were found for this investigation." if not relationships and not related_indicators else "Relationships are based on exact scan or threat-indicator evidence; resemblance alone is not treated as a campaign link."
        return ScamDnaGraph(scan_id=scan_id, nodes=nodes, edges=edges, relationships=relationships, deterministic_summary=summary)
