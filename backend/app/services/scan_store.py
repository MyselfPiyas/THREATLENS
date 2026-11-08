"""Small PostgREST adapter. Privileged credentials are used only for backend writes."""

from typing import Any
from uuid import UUID

import httpx
from fastapi import HTTPException, status

from app.core.config import Settings, get_settings
from app.services.auth import AuthenticatedPrincipal


class ScanStore:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def _base_url(self) -> str:
        if not self.settings.supabase_url or not self.settings.supabase_url.strip():
            raise HTTPException(status_code=503, detail="Supabase is not configured.")
        return f"{self.settings.supabase_url.rstrip('/')}/rest/v1"

    def _admin_headers(self, prefer: str | None = None) -> dict[str, str]:
        key = self.settings.supabase_admin_key_value
        if not key:
            raise HTTPException(
                status_code=503,
                detail="URL scan persistence is unavailable. Configure the backend-only SUPABASE_SECRET_KEY.",
            )
        # New sb_secret_* API keys are authenticated by the apikey header alone.
        # Legacy JWT service-role keys also need the matching Authorization value.
        headers = {"apikey": key, "Content-Type": "application/json"}
        if not key.startswith("sb_secret_"):
            headers["Authorization"] = f"Bearer {key}"
        if prefer:
            headers["Prefer"] = prefer
        return headers

    async def _request(
        self,
        method: str,
        table: str,
        *,
        headers: dict[str, str],
        params: dict[str, str] | None = None,
        json: Any = None,
    ) -> Any:
        try:
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=False) as client:
                response = await client.request(
                    method, f"{self._base_url()}/{table}", headers=headers, params=params, json=json
                )
        except (httpx.HTTPError, HTTPException) as error:
            if isinstance(error, HTTPException):
                raise
            raise RuntimeError("The scan database is temporarily unavailable.") from error
        if not response.is_success:
            # Never include provider bodies, which can contain schema details or target data.
            raise RuntimeError(f"The scan database rejected a {method} operation ({response.status_code}).")
        if response.status_code == 204 or not response.content:
            return None
        try:
            return response.json()
        except ValueError as error:
            raise RuntimeError("The scan database returned an invalid response.") from error

    async def create_scan(self, scan_id: UUID, user_id: UUID, normalized_url: str) -> None:
        await self._request(
            "POST", "scans", headers=self._admin_headers("return=minimal"),
            json={
                "id": str(scan_id), "user_id": str(user_id), "scan_type": "url",
                "target": normalized_url, "normalized_target": normalized_url,
                "status": "queued", "risk_level": "unknown", "risk_score": 0,
                "summary": "Scan queued; no assessment has completed.",
            },
        )

    async def update_scan(self, scan_id: UUID, values: dict[str, Any]) -> None:
        await self._request(
            "PATCH", "scans", headers=self._admin_headers("return=minimal"),
            params={"id": f"eq.{scan_id}"}, json=values,
        )

    async def add_event(
        self, scan_id: UUID, event_type: str, title: str, description: str,
        event_data: dict[str, Any] | None = None,
    ) -> None:
        await self._request(
            "POST", "scan_events", headers=self._admin_headers("return=minimal"),
            json={"scan_id": str(scan_id), "event_type": event_type, "title": title,
                  "description": description, "event_data": event_data or {}},
        )

    async def add_finding(self, scan_id: UUID, finding: dict[str, Any]) -> None:
        await self._request(
            "POST", "scan_findings", headers=self._admin_headers("return=minimal"),
            json={"scan_id": str(scan_id), **finding},
        )

    async def read_own_rows(
        self,
        principal: AuthenticatedPrincipal,
        table: str,
        params: dict[str, str],
    ) -> list[dict[str, Any]]:
        if not self.settings.supabase_key_value:
            raise HTTPException(status_code=503, detail="Supabase is not configured.")
        headers = {
            "apikey": self.settings.supabase_key_value,
            "Authorization": f"Bearer {principal.access_token}",
        }
        try:
            data = await self._request("GET", table, headers=headers, params=params)
        except RuntimeError as error:
            raise HTTPException(status_code=503, detail="Scan records are temporarily unavailable.") from error
        if not isinstance(data, list) or any(not isinstance(row, dict) for row in data):
            raise HTTPException(status_code=503, detail="Scan database returned an invalid response.")
        return data

    async def require_write_access(self) -> None:
        # Fail before creating a queued record if server-side persistence is unavailable.
        self._base_url()
        self._admin_headers()

    async def create_analysis(self, table: str, analysis_id: UUID, user_id: UUID, result: dict[str, Any]) -> None:
        await self._request("POST", table, headers=self._admin_headers("return=minimal"), json={"id": str(analysis_id), "user_id": str(user_id), "result": result})

    async def read_analysis(self, table: str, analysis_id: UUID, principal: AuthenticatedPrincipal) -> dict[str, Any] | None:
        rows = await self.read_own_rows(principal, table, {"select": "id,result", "id": f"eq.{analysis_id}", "limit": "1"})
        return rows[0] if rows else None

    async def admin_rows(self, table: str, params: dict[str, str]) -> list[dict[str, Any]]:
        data = await self._request("GET", table, headers=self._admin_headers(), params=params)
        if not isinstance(data, list) or any(not isinstance(row, dict) for row in data):
            raise RuntimeError("The scan database returned an invalid response.")
        return data

    async def upsert_relationship(self, relationship: dict[str, Any]) -> None:
        await self._request(
            "POST", "scan_relationships", headers=self._admin_headers("resolution=merge-duplicates,return=minimal"), json=relationship
        )

    async def read_own_relationships(self, scan_id: UUID, principal: AuthenticatedPrincipal) -> list[dict[str, Any]]:
        return await self.read_own_rows(principal, "scan_relationships", {"select": "id,source_scan_id,related_scan_id,relationship_type,confidence,evidence", "or": f"(source_scan_id.eq.{scan_id},related_scan_id.eq.{scan_id})", "order": "confidence.desc", "limit": "100"})

    async def create_passport(self, passport: dict[str, Any]) -> None:
        await self._request("POST", "trust_passports", headers=self._admin_headers("return=minimal"), json=passport)

    async def update_passport(self, passport_id: UUID, values: dict[str, Any]) -> None:
        await self._request("PATCH", "trust_passports", headers=self._admin_headers("return=minimal"), params={"id": f"eq.{passport_id}"}, json=values)

