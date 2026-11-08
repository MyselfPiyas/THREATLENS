from functools import lru_cache
from typing import TYPE_CHECKING

from app.core.config import get_settings

if TYPE_CHECKING:
    from supabase import Client


def _get_project_credentials(*, privileged: bool = False) -> tuple[str, str]:
    settings = get_settings()
    key = settings.supabase_admin_key_value if privileged else settings.supabase_key_value
    if not settings.supabase_url or not settings.supabase_url.strip() or not key:
        key_name = "SUPABASE_SECRET_KEY" if privileged else "SUPABASE_PUBLISHABLE_KEY"
        raise RuntimeError(f"Supabase is not configured. Set SUPABASE_URL and {key_name} in the backend environment.")
    return settings.supabase_url.rstrip("/"), key


@lru_cache
def get_supabase_client() -> "Client":
    """Return a backend client using the publishable key; user data remains subject to RLS."""
    from supabase import create_client

    url, key = _get_project_credentials()
    return create_client(url, key)


@lru_cache
def get_supabase_admin_client() -> "Client":
    """Return a privileged backend-only client. Never import this from frontend code."""
    from supabase import create_client
    from supabase.client import ClientOptions

    url, key = _get_project_credentials(privileged=True)
    return create_client(
        url,
        key,
        options=ClientOptions(auto_refresh_token=False, persist_session=False),
    )


def create_user_supabase_client(access_token: str) -> "Client":
    """Create a request-scoped client so database queries run under the caller's RLS identity."""
    from supabase import create_client
    from supabase.client import ClientOptions

    url, key = _get_project_credentials()
    return create_client(
        url,
        key,
        options=ClientOptions(
            headers={"Authorization": f"Bearer {access_token}"},
            auto_refresh_token=False,
            persist_session=False,
        ),
    )
