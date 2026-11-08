from uuid import UUID

import httpx
from fastapi import HTTPException, status

from app.core.config import Settings, get_settings
from app.services.auth import AuthenticatedPrincipal


async def ensure_scan_owner(
    scan_id: UUID,
    principal: AuthenticatedPrincipal,
    settings: Settings | None = None,
) -> UUID:
    """Verify ownership through PostgREST using the caller JWT, with RLS as a second boundary."""
    settings = settings or get_settings()
    if not settings.supabase_url or not settings.supabase_url.strip() or not settings.supabase_key_value:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scan ownership cannot be checked because Supabase is not configured.",
        )

    url = f"{settings.supabase_url.rstrip('/')}/rest/v1/scans"
    headers = {
        "apikey": settings.supabase_key_value,
        "Authorization": f"Bearer {principal.access_token}",
    }

    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
            response = await client.get(
                url,
                params={
                    "id": f"eq.{scan_id}",
                    "user_id": f"eq.{principal.user_id}",
                    "select": "id",
                    "limit": "1",
                },
                headers=headers,
            )
    except httpx.HTTPError as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scan ownership could not be verified.",
        ) from error

    if response.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scan ownership could not be verified.",
        )

    try:
        rows = response.json()
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scan ownership could not be verified.",
        ) from error

    if not isinstance(rows, list):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scan ownership could not be verified.",
        )
    if not rows:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    return scan_id
