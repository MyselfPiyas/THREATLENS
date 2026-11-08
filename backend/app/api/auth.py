from fastapi import APIRouter, Depends

from app.api.dependencies import get_current_principal
from app.schemas.auth import CurrentUserResponse
from app.services.auth import AuthenticatedPrincipal

router = APIRouter(prefix="/auth", tags=["authentication"])


@router.get("/me", response_model=CurrentUserResponse, summary="Return the authenticated user")
async def get_me(principal: AuthenticatedPrincipal = Depends(get_current_principal)) -> CurrentUserResponse:
    return CurrentUserResponse(id=principal.user_id, email=principal.email)
