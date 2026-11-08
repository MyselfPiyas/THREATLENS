from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.dependencies import get_current_principal, require_scan_owner
from app.schemas.identity import BrandReference, IdentityRequest, IdentityResult
from app.services.auth import AuthenticatedPrincipal
from app.services.identity import analyze_identity, brand_catalog
from app.services.scan_store import ScanStore

router = APIRouter(tags=["website identity"])


@router.get("/brands", response_model=list[BrandReference])
async def get_brands(_: AuthenticatedPrincipal = Depends(get_current_principal)) -> list[BrandReference]:
    return [BrandReference.model_validate(item) for item in brand_catalog()]


@router.post("/analyze/identity", response_model=IdentityResult, status_code=status.HTTP_200_OK)
async def analyze_website_identity(
    request: IdentityRequest,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> IdentityResult:
    if request.scan_id is not None:
        await require_scan_owner(request.scan_id, principal)
    result = analyze_identity(request.url, request.claimed_brand)
    output = IdentityResult(scan_id=request.scan_id, **result.as_evidence())
    if request.scan_id is not None:
        await ScanStore().add_finding(request.scan_id, {
            "category": "website_identity",
            "title": "Website identity analysis",
            "description": result.explanation,
            "severity": "suspicious" if result.suspicious_characters else "informational",
            "evidence": result.as_evidence(),
            "source": "threatlens_identity_rules",
            "confidence": result.confidence,
        })
    return output


@router.get("/scans/{scan_id}/identity", response_model=IdentityResult)
async def get_scan_identity(
    scan_id: UUID,
    _: UUID = Depends(require_scan_owner),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> IdentityResult:
    rows = await ScanStore().read_own_rows(principal, "scan_findings", {
        "select": "scan_id,evidence,category",
        "scan_id": f"eq.{scan_id}", "category": "eq.website_identity", "order": "created_at.desc", "limit": "1",
    })
    if not rows:
        raise HTTPException(status_code=404, detail="Identity analysis not found.")
    evidence = rows[0].get("evidence")
    if not isinstance(evidence, dict):
        raise HTTPException(status_code=503, detail="Identity analysis data is invalid.")
    return IdentityResult(scan_id=scan_id, **evidence)
