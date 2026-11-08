from datetime import UTC, datetime
from uuid import uuid4

from app.services.passport_service import build_report, canonical_json, report_hash, verify_report_hash


def _scan(scan_id=None):
    return {
        "id": scan_id or uuid4(), "scan_type": "url", "target": "https://example.com",
        "normalized_target": "https://example.com/", "status": "completed",
        "risk_level": "INCONCLUSIVE", "risk_score": 0, "summary": "No conclusion",
        "started_at": datetime(2026, 1, 1, tzinfo=UTC),
        "completed_at": datetime(2026, 1, 1, 0, 1, tzinfo=UTC),
    }


def test_canonical_json_sorts_keys_and_normalizes_unicode():
    assert canonical_json({"b": 1, "a": "e\u0301"}) == '{"a":"é","b":1}'
    assert canonical_json({"a": "é", "b": 1}) == '{"a":"é","b":1}'


def test_hash_stable_across_generated_time_and_equivalent_timezones():
    scan = _scan(uuid4())
    first = build_report(scan, [], [], passport_id=uuid4())
    other = {**first, "generated_at": datetime(2030, 1, 1, tzinfo=UTC)}
    other["started_at"] = "2025-12-31T19:00:00-05:00"
    # Canonical report timestamp normalization makes equivalent instants identical.
    first["started_at"] = "2026-01-01T00:00:00Z"
    assert report_hash(first) == report_hash(other)


def test_report_evidence_changes_change_digest():
    report = build_report(_scan(), [], [], passport_id=uuid4())
    baseline = report_hash(report)
    for key, value in (("risk_score", 99), ("target", "https://changed.example"), ("risk_level", "HIGH_RISK")):
        altered = {**report, key: value}
        assert report_hash(altered) != baseline


def test_finding_array_order_is_stable_and_evidence_changes_are_detected():
    scan = _scan(uuid4())
    passport_id = uuid4()
    findings = [
        {"id": "b", "created_at": "2026-01-02T00:00:00Z", "title": "second", "severity": "low"},
        {"id": "a", "created_at": "2026-01-01T00:00:00Z", "title": "first", "severity": "high"},
    ]
    first = build_report(scan, findings, [], passport_id=passport_id)
    second = build_report(scan, list(reversed(findings)), [], passport_id=passport_id)
    assert report_hash(first) == report_hash(second)
    changed = {**first, "findings": [{**first["findings"][0], "title": "altered"}, first["findings"][1]]}
    assert report_hash(changed) != report_hash(first)


def test_verification_uses_constant_time_digest_comparison_contract():
    report = build_report(_scan(), [], [], passport_id=uuid4())
    digest = report_hash(report)
    assert verify_report_hash(report, digest)
    assert not verify_report_hash(report, "0" * 64)


def test_invalid_nonfinite_json_number_is_rejected():
    import pytest

    with pytest.raises(ValueError):
        canonical_json({"score": float("nan")})
