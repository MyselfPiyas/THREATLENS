from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException

from app.api.dependencies import get_current_principal, require_scan_owner
from app.schemas.tls import SecurityHeadersRequest, TlsRequest, TlsResult, TlsStoredResult
from app.services.auth import AuthenticatedPrincipal
from app.services.scan_store import ScanStore
from app.services.tls_analysis import analyze_security_headers, analyze_tls

router = APIRouter(tags=["TLS and passive security"])


async def _ensure_owned(scan_id: UUID | None, principal: AuthenticatedPrincipal) -> None:
    if scan_id is not None:
        await require_scan_owner(scan_id, principal)


@router.post("/analyze/tls", response_model=TlsResult)
async def post_tls(request: TlsRequest, principal: AuthenticatedPrincipal = Depends(get_current_principal)) -> TlsResult:
    await _ensure_owned(request.scan_id, principal)
    result = await analyze_tls(request.url)
    if request.scan_id is not None:
        await ScanStore().add_finding(request.scan_id, {"category": "tls_analysis", "title": "TLS certificate analysis", "description": "Passive TLS certificate observations were recorded.", "severity": "informational", "evidence": result, "source": "threatlens_tls_inspector", "confidence": 0.95 if result.get("available") else 0.5})
    return TlsResult(scan_id=request.scan_id, **result)


@router.post("/analyze/security-headers")
async def post_security_headers(request: SecurityHeadersRequest, principal: AuthenticatedPrincipal = Depends(get_current_principal)) -> dict:
    await _ensure_owned(request.scan_id, principal)
    result = await analyze_security_headers(request.url)
    if request.scan_id is not None:
        severity = "suspicious" if result["missing"] else "informational"
        await ScanStore().add_finding(request.scan_id, {"category": "security_headers", "title": "HTTP security header checklist", "description": "Passive HTTP response headers were checked without fetching or executing the response body.", "severity": severity, "evidence": result, "source": "threatlens_security_headers", "confidence": 0.9})
    return {"scan_id": request.scan_id, **result}


@router.get("/scans/{scan_id}/tls", response_model=TlsStoredResult)
async def get_tls(scan_id: UUID, _: UUID = Depends(require_scan_owner), principal: AuthenticatedPrincipal = Depends(get_current_principal)) -> TlsStoredResult:
    rows = await ScanStore().read_own_rows(principal, "scan_findings", {"select": "scan_id,category,evidence", "scan_id": f"eq.{scan_id}", "category": "in.(tls_analysis,security_headers)", "order": "created_at.desc", "limit": "20"})
    tls = next((row.get("evidence") for row in rows if row.get("category") == "tls_analysis" and isinstance(row.get("evidence"), dict)), None)
    headers = next((row.get("evidence") for row in rows if row.get("category") == "security_headers" and isinstance(row.get("evidence"), dict)), None)
    if tls is None and headers is None:
        raise HTTPException(status_code=404, detail="TLS analysis not found.")
    return TlsStoredResult(scan_id=scan_id, tls=tls, security_headers=headers)
