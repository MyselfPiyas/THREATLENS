from dataclasses import dataclass, field
from uuid import UUID

import httpx
from fastapi import HTTPException, status

from app.core.config import Settings, get_settings


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    user_id: UUID
    email: str | None
    access_token: str = field(repr=False)


async def resolve_access_token(
    access_token: str,
    settings: Settings | None = None,
) -> AuthenticatedPrincipal:
    settings = settings or get_settings()
    if not settings.supabase_url or not settings.supabase_url.strip() or not settings.supabase_key_value:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service is not configured.",
        )

    url = f"{settings.supabase_url.rstrip('/')}/auth/v1/user"
    headers = {
        "apikey": settings.supabase_key_value,
        "Authorization": f"Bearer {access_token}",
    }

    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
            response = await client.get(url, headers=headers)
    except httpx.HTTPError as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service is temporarily unavailable.",
        ) from error

    if response.status_code in {401, 403}:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="The access token is invalid or expired.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if response.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service is temporarily unavailable.",
        )

    try:
        payload = response.json()
        user_id = UUID(payload["id"])
        email = payload.get("email")
    except (ValueError, KeyError, TypeError) as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="The authentication service returned an invalid user.",
        ) from error

    return AuthenticatedPrincipal(
        user_id=user_id,
        email=email if isinstance(email, str) else None,
        access_token=access_token,
    )
