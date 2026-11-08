from fastapi import APIRouter

from app.core.config import get_settings
from app.schemas.health import HealthResponse

router = APIRouter(prefix="/health", tags=["health"])


@router.get("", response_model=HealthResponse, summary="Check API readiness")
async def health_check() -> HealthResponse:
    settings = get_settings()
    return HealthResponse(
        status="ok",
        service="threatlens-api",
        supabase_configured=settings.supabase_is_configured,
        scan_persistence_configured=bool(settings.supabase_url and settings.supabase_admin_key_value),
    )

