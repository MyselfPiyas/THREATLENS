"""Deterministic Trust Passport report generation and integrity verification."""

from __future__ import annotations

import hashlib
import hmac
import json
import unicodedata
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from app.core.config import Settings, get_settings
from app.services.auth import AuthenticatedPrincipal
from app.services.scan_store import ScanStore


def _json_value(value: Any) -> Any:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            normalized_key = str(key)
            if normalized_key.endswith("_at") and isinstance(item, (str, datetime)):
                normalized[normalized_key] = _normalize_timestamp(item) if isinstance(item, str) else _json_value(item)
            else:
                normalized[normalized_key] = _json_value(item)
        return normalized
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    return value


def canonical_json(value: Any) -> str:
    """Return the single canonical JSON representation used for hashing."""
    return json.dumps(_json_value(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def report_hash(report: dict[str, Any]) -> str:
    """Hash stable report evidence; generated_at is envelope metadata, not evidence."""
    stable = {key: value for key, value in report.items() if key != "generated_at"}
    return hashlib.sha256(canonical_json(stable).encode("utf-8")).hexdigest()


def verify_report_hash(report: dict[str, Any], expected_hash: str) -> bool:
    """Compare a computed digest to the stored reference in constant time."""
    return hmac.compare_digest(report_hash(report), expected_hash.lower())


def _normalize_timestamp(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return value
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def build_report(scan: dict[str, Any], findings: list[dict[str, Any]], events: list[dict[str, Any]], settings: Settings | None = None, passport_id: UUID | None = None) -> dict[str, Any]:
    settings = settings or get_settings()
    report = {
        "report_version": settings.passport_report_version,
        "scanner_version": settings.passport_scanner_version,
        "passport_id": str(passport_id or uuid4()),
        "scan_id": str(scan["id"]),
        "scan_type": scan.get("scan_type"),
        "target": scan.get("target"),
        "normalized_target": scan.get("normalized_target"),
        "status": scan.get("status"),
        "risk_level": scan.get("risk_level"),
        "risk_score": scan.get("risk_score"),
        "summary": scan.get("summary"),
        "started_at": _normalize_timestamp(scan.get("started_at")),
        "completed_at": _normalize_timestamp(scan.get("completed_at")),
        "findings": [{"id": row.get("id"), "category": row.get("category"), "title": row.get("title"), "description": row.get("description"), "severity": row.get("severity"), "confidence": row.get("confidence"), "source": row.get("source"), "evidence": row.get("evidence", {})} for row in sorted(findings, key=lambda item: (str(item.get("created_at", "")), str(item.get("id", ""))))],
        "events": [{"id": row.get("id"), "event_type": row.get("event_type"), "title": row.get("title"), "occurred_at": _normalize_timestamp(row.get("occurred_at")), "event_data": row.get("event_data", {})} for row in sorted(events, key=lambda item: (str(item.get("occurred_at", "")), str(item.get("id", ""))))],
        "generated_at": datetime.now(UTC),
    }
    return report


async def load_owned_report(scan_id: UUID, principal: AuthenticatedPrincipal, store: ScanStore | None = None, passport_id: UUID | None = None) -> dict[str, Any]:
    store = store or ScanStore()
    scans = await store.read_own_rows(principal, "scans", {"select": "id,user_id,scan_type,target,normalized_target,status,risk_level,risk_score,summary,started_at,completed_at,created_at", "id": f"eq.{scan_id}", "user_id": f"eq.{principal.user_id}", "limit": "1"})
    if not scans:
        return {}
    findings = await store.read_own_rows(principal, "scan_findings", {"select": "id,scan_id,category,title,description,severity,evidence,source,confidence,created_at", "scan_id": f"eq.{scan_id}", "order": "created_at.asc", "limit": "200"})
    events = await store.read_own_rows(principal, "scan_events", {"select": "id,scan_id,event_type,title,description,event_data,occurred_at", "scan_id": f"eq.{scan_id}", "order": "occurred_at.asc", "limit": "500"})
    return build_report(scans[0], findings, events, passport_id=passport_id)

