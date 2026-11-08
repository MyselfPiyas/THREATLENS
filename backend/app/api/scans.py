from datetime import UTC, datetime
import logging
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.dependencies import get_current_principal, require_scan_owner
from app.schemas.scans import ScanAccepted, ScanEvent, ScanFinding, ScanRecord, ScanStatus, UrlScanRequest
from app.services.auth import AuthenticatedPrincipal
from app.services.scan_queue import ScanJob, scan_queue
from app.services.scan_store import ScanStore

router = APIRouter(prefix="/scans", tags=["URL scans"])
logger = logging.getLogger("threatlens.api.scans")


@router.post("/url", response_model=ScanAccepted, status_code=status.HTTP_202_ACCEPTED)
async def submit_url_scan(
    request: UrlScanRequest,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> ScanAccepted:
    store = ScanStore()
    await store.require_write_access()
    scan_id = uuid4()
    await store.create_scan(scan_id, principal.user_id, request.url)
    try:
        await store.add_event(
            scan_id, "url_received", "URL received",
            "An authenticated user submitted a URL for a safe, bounded inspection.",
            {"scan_type": "url"},
        )
    except Exception as error:
        logger.error("Could not persist the initial scan event (%s)", type(error).__name__, extra={"scan_id": str(scan_id)})
        try:
            await store.update_scan(scan_id, {
                "status": "failed", "risk_level": "unknown",
                "summary": "The investigation could not be queued. No assessment ran.",
                "completed_at": datetime.now(UTC).isoformat(),
            })
        except Exception as update_error:
            logger.error("Could not mark the interrupted scan failed (%s)", type(update_error).__name__, extra={"scan_id": str(scan_id)})
        raise HTTPException(status_code=503, detail="The investigation could not be queued. Try again shortly.") from error
    if not scan_queue.enqueue(ScanJob(scan_id=scan_id, user_id=principal.user_id, url=request.url)):
        await store.update_scan(scan_id, {
            "status": "failed", "risk_level": "unknown",
            "summary": "The scan queue is busy. No safety conclusion can be drawn.",
            "completed_at": datetime.now(UTC).isoformat(),
        })
        raise HTTPException(status_code=503, detail="The scan queue is currently full. Try again shortly.")
    return ScanAccepted(scan_id=scan_id, status="queued", status_url=f"/api/v1/scans/{scan_id}/status")


@router.get("", response_model=list[ScanRecord])
async def list_scans(
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=10000),
) -> list[ScanRecord]:
    rows = await ScanStore().read_own_rows(principal, "scans", {
        "select": "id,user_id,scan_type,target,normalized_target,status,risk_level,risk_score,summary,started_at,completed_at,created_at",
        "user_id": f"eq.{principal.user_id}", "order": "created_at.desc",
        "limit": str(limit), "offset": str(offset),
    })
    return [ScanRecord.model_validate(row) for row in rows]


async def _owned_scan(scan_id: UUID, principal: AuthenticatedPrincipal) -> dict:
    rows = await ScanStore().read_own_rows(principal, "scans", {
        "select": "id,user_id,scan_type,target,normalized_target,status,risk_level,risk_score,summary,started_at,completed_at,created_at",
        "id": f"eq.{scan_id}", "user_id": f"eq.{principal.user_id}", "limit": "1",
    })
    if not rows:
        # Ownership was already verified; this handles a concurrent deletion.
        raise HTTPException(status_code=404, detail="Scan not found.")
    return rows[0]


@router.get("/{scan_id}/status", response_model=ScanStatus)
async def get_scan_status(
    scan_id: UUID,
    _: UUID = Depends(require_scan_owner),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> ScanStatus:
    row = await _owned_scan(scan_id, principal)
    return ScanStatus(scan_id=scan_id, status=row["status"], risk_level=row["risk_level"], risk_score=row["risk_score"], summary=row["summary"])


@router.get("/{scan_id}/findings", response_model=list[ScanFinding])
async def get_scan_findings(
    scan_id: UUID,
    _: UUID = Depends(require_scan_owner),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> list[ScanFinding]:
    rows = await ScanStore().read_own_rows(principal, "scan_findings", {
        "select": "id,scan_id,category,title,description,severity,evidence,source,confidence,created_at",
        "scan_id": f"eq.{scan_id}", "order": "created_at.asc", "limit": "100",
    })
    return [ScanFinding.model_validate(row) for row in rows]


@router.get("/{scan_id}/events", response_model=list[ScanEvent])
async def get_scan_events(
    scan_id: UUID,
    _: UUID = Depends(require_scan_owner),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> list[ScanEvent]:
    rows = await ScanStore().read_own_rows(principal, "scan_events", {
        "select": "id,scan_id,event_type,title,description,event_data,occurred_at",
        "scan_id": f"eq.{scan_id}", "order": "occurred_at.asc", "limit": "200",
    })
    return [ScanEvent.model_validate(row) for row in rows]


@router.get("/{scan_id}", response_model=ScanRecord)
async def get_scan(
    scan_id: UUID,
    _: UUID = Depends(require_scan_owner),
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
) -> ScanRecord:
    return ScanRecord.model_validate(await _owned_scan(scan_id, principal))
