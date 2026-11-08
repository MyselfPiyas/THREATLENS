from uuid import UUID, uuid4

import anyio
import pytest

from app.schemas.intelligence import Relationship
from app.services.scam_dna_ai_service import interpret_scam_dna
from app.services.threat_intelligence_service import normalize_indicator


def test_indicator_normalization_and_validation():
    assert normalize_indicator("DOMAIN", "Example.COM.") == ("domain", "example.com")
    assert normalize_indicator("url", "HTTPS://Example.COM/path#fragment") == ("url", "https://example.com/path")
    with pytest.raises(ValueError):
        normalize_indicator("domain", "")
    with pytest.raises(ValueError):
        normalize_indicator("unsupported", "value")


def test_relationship_confidence_is_bounded():
    relationship = Relationship(source_scan_id=uuid4(), related_scan_id=uuid4(), relationship_type="shared_domain", confidence=0.75)
    assert relationship.confidence == 0.75
    with pytest.raises(ValueError):
        Relationship(source_scan_id=uuid4(), related_scan_id=uuid4(), relationship_type="shared_domain", confidence=1.5)


def test_ai_interpretation_rejects_uncited_evidence(monkeypatch):
    async def fake_complete(*args, **kwargs):
        return {"summary": "Possible link", "common_tactics": [], "investigation_priorities": [], "evidence_gaps": [], "cited_evidence_ids": ["not-supplied"], "uncertainty": "Evidence is limited."}
    monkeypatch.setattr("app.services.scam_dna_ai_service.complete_json", fake_complete)
    result = anyio.run(interpret_scam_dna, uuid4(), [{"id": "e-1", "type": "shared_domain", "confidence": 0.7}])
    assert result is not None
    assert result["cited_evidence_ids"] == []
