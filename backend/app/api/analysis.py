from __future__ import annotations

from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status

from app.api.dependencies import get_current_principal
from app.schemas.analysis import MessageRequest, MessageResult, QrResult
from app.services.auth import AuthenticatedPrincipal
from app.services.message_analysis import analyze_message, optional_llm_review
from app.services.qr_analysis import decode_qr
from app.services.scan_store import ScanStore
from app.services.scan_queue import ScanJob, scan_queue
from app.scanners.url_validation import UnsafeTarget, normalize_url

router = APIRouter(tags=["message and QR analysis"])


@router.post("/analyze/message", response_model=MessageResult)
async def analyze_message_endpoint(request: MessageRequest, principal: AuthenticatedPrincipal = Depends(get_current_principal)) -> MessageResult:
    baseline = analyze_message(request.content)
    analysis = await optional_llm_review(request.content, baseline) if request.allow_llm else baseline
    analysis_id = uuid4()
    result = {"risk_level": analysis.risk_level, "risk_score": analysis.risk_score, "detected_tactics": analysis.detected_tactics, "highlighted_phrases": analysis.highlighted_phrases, "extracted_indicators": analysis.extracted_indicators, "evidence": analysis.evidence, "explanation": analysis.explanation, "recommended_actions": analysis.recommended_actions, "source": analysis.source}
    await ScanStore().create_analysis("message_analyses", analysis_id, principal.user_id, result)
    return MessageResult(analysis_id=analysis_id, **result)


@router.get("/analyze/message/{analysis_id}", response_model=MessageResult)
async def get_message_analysis(analysis_id: UUID, principal: AuthenticatedPrincipal = Depends(get_current_principal)) -> MessageResult:
    row = await ScanStore().read_analysis("message_analyses", analysis_id, principal)
    if not row or not isinstance(row.get("result"), dict):
        raise HTTPException(status_code=404, detail="Message analysis not found.")
    return MessageResult(analysis_id=analysis_id, **row["result"])


@router.post("/analyze/qr", response_model=QrResult, status_code=status.HTTP_200_OK)
async def analyze_qr_endpoint(file: UploadFile = File(...), principal: AuthenticatedPrincipal = Depends(get_current_principal)) -> QrResult:
    if file.content_type not in {"image/png", "image/jpeg", "image/webp"}:
        raise HTTPException(status_code=415, detail="Upload a PNG, JPEG, or WEBP image.")
    data = await file.read(5 * 1024 * 1024 + 1)
    if len(data) > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="QR image exceeds the 5 MB limit.")
    try:
        content = decode_qr(data)
    except (ValueError, RuntimeError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    analysis_id = uuid4()
    url_scan_id = None
    risk_level = None
    risk_score = None
    evidence = ["QR content was decoded locally; the destination was not visited by the browser."]
    content_type = "text"
    try:
        normalized = normalize_url(content)
        content_type = "url"
        evidence.append("The decoded content is an HTTP(S) URL and can be submitted to the bounded URL scanner.")
        store = ScanStore()
        await store.require_write_access()
        url_scan_id = uuid4()
        await store.create_scan(url_scan_id, principal.user_id, normalized)
        await store.add_event(url_scan_id, "url_received", "URL received from QR code", "The decoded URL was queued for the same bounded URL investigation pipeline.", {"source": "qr_analysis"})
        if not scan_queue.enqueue(ScanJob(scan_id=url_scan_id, user_id=principal.user_id, url=normalized)):
            raise HTTPException(status_code=503, detail="The URL scan queue is currently full. Try again shortly.")
    except UnsafeTarget:
        normalized = None
        evidence.append("The decoded content is not an accepted public HTTP(S) URL.")
    result = {"decoded": True, "content_type": content_type, "extracted_content": content, "url_scan_id": url_scan_id, "risk_level": risk_level, "risk_score": risk_score, "evidence": evidence, "explanation": "QR decoding is separate from destination inspection; no arbitrary QR destination was automatically visited."}
    await ScanStore().create_analysis("qr_analyses", analysis_id, principal.user_id, result)
    return QrResult(analysis_id=analysis_id, **result)


@router.get("/analyze/qr/{analysis_id}", response_model=QrResult)
async def get_qr_analysis(analysis_id: UUID, principal: AuthenticatedPrincipal = Depends(get_current_principal)) -> QrResult:
    row = await ScanStore().read_analysis("qr_analyses", analysis_id, principal)
    if not row or not isinstance(row.get("result"), dict):
        raise HTTPException(status_code=404, detail="QR analysis not found.")
    return QrResult(analysis_id=analysis_id, **row["result"])
