from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

from app.services.scan_store import ScanStore


SUPPORTED_TYPES = {"domain", "url", "ipv4", "ipv6", "sha256"}


def normalize_indicator(indicator_type: str, value: str) -> tuple[str, str]:
    kind = indicator_type.strip().casefold()
    if kind not in SUPPORTED_TYPES:
        raise ValueError("Unsupported indicator type.")
    normalized = value.strip()
    if not normalized:
        raise ValueError("Indicator value must not be blank.")
    if kind == "domain":
        normalized = normalized.rstrip(".").casefold()
    elif kind == "url":
        parsed = urlsplit(normalized)
        if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("URL indicators must be absolute HTTP(S) URLs.")
        normalized = urlunsplit((parsed.scheme.casefold(), parsed.netloc.casefold(), parsed.path or "/", parsed.query, ""))
    elif kind in {"ipv4", "ipv6", "sha256"}:
        normalized = normalized.casefold()
    return kind, normalized


class ThreatIntelligenceService:
    def __init__(self, store: ScanStore | None = None) -> None:
        self.store = store or ScanStore()

    async def list_indicators(self, page: int = 1, page_size: int = 25, search: str | None = None, indicator_type: str | None = None) -> list[dict[str, Any]]:
        params = {"select": "id,indicator_type,indicator_value,source,threat_category,confidence,first_seen,last_seen,metadata", "order": "last_seen.desc", "limit": str(page_size), "offset": str((page - 1) * page_size)}
        if search:
            params["indicator_value"] = f"ilike.*{search.strip()}*"
        if indicator_type:
            kind, _ = normalize_indicator(indicator_type, "x.example" if indicator_type == "domain" else ("https://example.com" if indicator_type == "url" else "x"))
            params["indicator_type"] = f"eq.{kind}"
        return await self.store.admin_rows("threat_indicators", params)

    async def overview(self) -> dict[str, Any]:
        rows = await self.store.admin_rows("threat_indicators", {"select": "indicator_type,source,threat_category,confidence,last_seen", "order": "last_seen.desc", "limit": "1000"})
        sources = sorted({str(row.get("source")) for row in rows if row.get("source")})
        categories: dict[str, int] = {}
        types: dict[str, int] = {}
        for row in rows:
            categories[str(row.get("threat_category", "unknown"))] = categories.get(str(row.get("threat_category", "unknown")), 0) + 1
            types[str(row.get("indicator_type", "unknown"))] = types.get(str(row.get("indicator_type", "unknown")), 0) + 1
        return {"indicator_count": len(rows), "sources": sources, "source_count": len(sources), "categories": categories, "types": types, "last_updated": rows[0].get("last_seen") if rows else None}

    async def related_indicators(self, scan: dict[str, Any]) -> list[dict[str, Any]]:
        target = str(scan.get("normalized_target") or scan.get("target") or "")
        parsed = urlsplit(target)
        values = [("url", target), ("domain", parsed.hostname.casefold() if parsed.hostname else "")]
        results: list[dict[str, Any]] = []
        for kind, value in values:
            if not value:
                continue
            rows = await self.store.admin_rows("threat_indicators", {"select": "id,indicator_type,indicator_value,source,threat_category,confidence,first_seen,last_seen,metadata", "indicator_type": f"eq.{kind}", "indicator_value": f"eq.{value}", "limit": "20"})
            results.extend(rows)
        return results
