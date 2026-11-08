from typing import Literal

from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: Literal["ok"]
    service: str
    supabase_configured: bool
    scan_persistence_configured: bool

