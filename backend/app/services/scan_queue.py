"""Bounded in-process queue for URL investigations."""

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from app.core.config import get_settings
from app.scanners.url_scanner import ScanOutcome, inspect_url
from app.services.scan_store import ScanStore

logger = logging.getLogger("threatlens.scan_queue")


@dataclass(frozen=True)
class ScanJob:
    scan_id: UUID
    user_id: UUID
    url: str


class ScanQueue:
    def __init__(self, capacity: int = 64, workers: int = 2) -> None:
        self.capacity = capacity
        self.worker_count = workers
        self._queue: asyncio.Queue[ScanJob] | None = None
        self._workers: list[asyncio.Task[None]] = []
        self._stopping = False

    async def start(self) -> None:
        if self._queue is not None:
            return
        self._stopping = False
        self._queue = asyncio.Queue(maxsize=self.capacity)
        self._workers = [asyncio.create_task(self._work(), name=f"url-scan-worker-{index + 1}") for index in range(self.worker_count)]

    async def stop(self) -> None:
        workers, self._workers = self._workers, []
        self._stopping = True
        self._queue = None
        for worker in workers:
            worker.cancel()
        if workers:
            await asyncio.gather(*workers, return_exceptions=True)

    def enqueue(self, job: ScanJob) -> bool:
        if self._queue is None or self._queue.full():
            return False
        self._queue.put_nowait(job)
        return True

    async def _work(self) -> None:
        queue = self._queue
        assert queue is not None
        while True:
            job = await queue.get()
            try:
                await self._process(job)
            except asyncio.CancelledError:
                logger.info("URL scan worker cancelled", extra={"scan_id": str(job.scan_id)})
                store = ScanStore()
                try:
                    await store.update_scan(job.scan_id, {
                        "status": "failed", "risk_level": "INCONCLUSIVE",
                        "summary": "The scan was interrupted before completion. No safety conclusion can be drawn.",
                        "completed_at": datetime.now(UTC).isoformat(),
                    })
                    await store.add_event(
                        job.scan_id,
                        "scan_cancelled",
                        "Investigation interrupted",
                        "The worker stopped before completing the scan.",
                        {"risk_level": "INCONCLUSIVE"},
                    )
                except Exception:
                    logger.exception("Unable to save interrupted URL scan state", extra={"scan_id": str(job.scan_id)})
                raise
            except Exception:
                logger.exception("URL scan job failed", extra={"scan_id": str(job.scan_id)})
                try:
                    await ScanStore().update_scan(job.scan_id, {
                        "status": "failed", "risk_level": "INCONCLUSIVE",
                        "summary": "The scan could not be completed. No safety conclusion can be drawn.",
                        "completed_at": datetime.now(UTC).isoformat(),
                    })
                except Exception:
                    logger.exception("Unable to save failed URL scan state", extra={"scan_id": str(job.scan_id)})
            finally:
                queue.task_done()

    async def _process(self, job: ScanJob) -> None:
        store = ScanStore()
        settings = get_settings()
        await store.update_scan(job.scan_id, {"status": "running", "started_at": datetime.now(UTC).isoformat()})

        async def save_event(event_type: str, title: str, description: str, event_data: dict) -> None:
            await store.add_event(job.scan_id, event_type, title, description, event_data)

        try:
            outcome = await asyncio.wait_for(
                inspect_url(job.url, event_sink=save_event, settings=settings),
                timeout=settings.url_scan_job_timeout_seconds,
            )
        except asyncio.TimeoutError:
            await save_event("scan_timeout", "Investigation time limit reached", "The configured total scan time limit was reached.", {"timeout_seconds": settings.url_scan_job_timeout_seconds})
            await save_event("findings_generated", "Findings generated", "No complete finding set was available before timeout.", {"finding_count": 0})
            await save_event("risk_classified", "Risk classification completed", "The scan was classified INCONCLUSIVE because the time limit was reached.", {"risk_level": "INCONCLUSIVE", "risk_score": 0})
            outcome = ScanOutcome(
                risk_level="INCONCLUSIVE", risk_score=0,
                summary="The scan exceeded its time limit. No safety conclusion can be drawn.",
            )
        for finding in outcome.findings:
            await store.add_finding(job.scan_id, {
                "category": finding.category, "title": finding.title,
                "description": finding.description, "severity": finding.severity,
                "evidence": finding.evidence, "source": finding.source,
                "confidence": finding.confidence,
            })
        await store.update_scan(job.scan_id, {
            "status": "completed", "risk_level": outcome.risk_level,
            "risk_score": outcome.risk_score, "summary": outcome.summary,
            "completed_at": datetime.now(UTC).isoformat(),
        })


scan_queue = ScanQueue()
