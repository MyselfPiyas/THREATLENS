from __future__ import annotations

from datetime import datetime, timezone
import asyncio
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

import httpx

from app.services.scan_store import ScanStore


SUPPORTED_TYPES = {"domain", "url", "ipv4", "ipv6", "sha256"}
OPENPHISH_FEED_URL = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
OPENPHISH_SOURCE = "openphish"
OPENPHISH_REFRESH_SECONDS = 12 * 60 * 60
OPENPHISH_MAX_BYTES = 2 * 1024 * 1024
_openphish_last_refresh: datetime | None = None
_openphish_refresh_lock = asyncio.Lock()


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

    async def refresh_openphish(self, force: bool = False) -> dict[str, Any]:
        """Fetch and persist the public OpenPhish community URL feed, at most every 12 hours.

        The feed contains URLs only. No listed destination is visited. The provider does not
        publish numeric confidence, so metadata explicitly records our source-based score.
        """
        global _openphish_last_refresh
        async with _openphish_refresh_lock:
            now = datetime.now(timezone.utc)
            if not force and _openphish_last_refresh and (now - _openphish_last_refresh).total_seconds() < OPENPHISH_REFRESH_SECONDS:
                return {"source": OPENPHISH_SOURCE, "status": "cached", "updated_at": _openphish_last_refresh.isoformat(), "indicators_upserted": 0}

            timeout = httpx.Timeout(connect=5.0, read=12.0, write=5.0, pool=5.0)
            try:
                async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, trust_env=False) as client:
                    async with client.stream("GET", OPENPHISH_FEED_URL, headers={"Accept": "text/plain", "User-Agent": "THREATLENS threat-feed sync"}) as response:
                        if response.status_code != 200:
                            raise RuntimeError(f"OpenPhish feed is temporarily unavailable (HTTP {response.status_code}).")
                        length = response.headers.get("content-length")
                        if length and int(length) > OPENPHISH_MAX_BYTES:
                            raise RuntimeError("OpenPhish feed exceeded the configured size limit.")
                        chunks: list[bytes] = []
                        size = 0
                        async for chunk in response.aiter_bytes():
                            size += len(chunk)
                            if size > OPENPHISH_MAX_BYTES:
                                raise RuntimeError("OpenPhish feed exceeded the configured size limit.")
                            chunks.append(chunk)
                body = b"".join(chunks).decode("utf-8-sig")
            except (httpx.HTTPError, UnicodeDecodeError, ValueError) as error:
                raise RuntimeError("OpenPhish feed could not be retrieved or validated.") from error

            fetched_at = datetime.now(timezone.utc)
            records: list[dict[str, Any]] = []
            seen: set[str] = set()
            for line in body.splitlines():
                candidate = line.strip()
                if not candidate or candidate.startswith("#"):
                    continue
                try:
                    kind, value = normalize_indicator("url", candidate)
                    parsed = urlsplit(value)
                    # Ignore malformed values and nonstandard ports; entries are never fetched.
                    if parsed.username or parsed.password or parsed.port not in (None, 80, 443):
                        continue
                    host = parsed.hostname
                    if not host or len(value) > 2048 or value in seen:
                        continue
                    seen.add(value)
                except (ValueError, UnicodeError):
                    continue
                records.append({
                    "indicator_type": kind,
                    "indicator_value": value,
                    "source": OPENPHISH_SOURCE,
                    "threat_category": "phishing",
                    # Internal source-based confidence, not a score supplied by OpenPhish.
                    "confidence": 0.95,
                    # Leave first_seen to the database default on insert; omitting it from
                    # the upsert also preserves the original timestamp on later refreshes.
                    "last_seen": fetched_at.isoformat(),
                    "metadata": {
                        "provider": "OpenPhish Community Feed",
                        "feed_url": OPENPHISH_FEED_URL,
                        "feed_type": "community_phishing_url_feed",
                        "confidence_basis": "THREATLENS source-based score; provider publishes no numeric confidence.",
                        "retrieved_at": fetched_at.isoformat(),
                    },
                })
                if len(records) >= 5000:
                    break

            if not records:
                raise RuntimeError("OpenPhish returned no valid indicators; no clean result was recorded.")
            stored = await self.store.upsert_threat_indicators(records)
            _openphish_last_refresh = fetched_at
            return {"source": OPENPHISH_SOURCE, "status": "updated", "updated_at": fetched_at.isoformat(), "indicators_upserted": len(stored)}

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
