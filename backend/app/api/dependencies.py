from uuid import UUID

from fastapi import Depends, HTTPException, Path, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.services.auth import AuthenticatedPrincipal, resolve_access_token
from app.services.ownership import ensure_scan_owner

bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_principal(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> AuthenticatedPrincipal:
    if credentials is None or credentials.scheme.lower() != "bearer" or not credentials.credentials.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A valid bearer token is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return await resolve_access_token(credentials.credentials)


async def require_scan_owner(
    scan_id: UUID = Path(..., description="The scan the user is requesting."),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> UUID:
    """Reusable dependency required on every future scan-specific API endpoint."""
    return await ensure_scan_owner(scan_id, principal)
