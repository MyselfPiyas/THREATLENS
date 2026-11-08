import asyncio
from uuid import UUID

from app.services import scan_queue as scan_queue_module
from app.services.scan_queue import ScanJob, ScanQueue


def test_stopping_active_worker_marks_scan_inconclusive(monkeypatch) -> None:
    updated: list[tuple[UUID, dict]] = []
    events: list[tuple[UUID, str]] = []
    started = asyncio.Event()

    class FakeStore:
        async def update_scan(self, scan_id: UUID, values: dict) -> None:
            updated.append((scan_id, values))

        async def add_event(self, scan_id: UUID, event_type: str, *args, **kwargs) -> None:
            events.append((scan_id, event_type))

    monkeypatch.setattr(scan_queue_module, "ScanStore", FakeStore)
    queue = ScanQueue(capacity=1, workers=1)
    job = ScanJob(
        UUID("bc02b6aa-f06e-4fc0-9907-a09155abceaf"),
        UUID("28499fd4-a8a2-4f82-b9b5-27cfb29df4cb"),
        "https://example.com",
    )

    async def block_until_cancelled(job: ScanJob) -> None:
        started.set()
        await asyncio.Event().wait()

    async def exercise() -> None:
        queue._process = block_until_cancelled
        await queue.start()
        assert queue.enqueue(job)
        await started.wait()
        await queue.stop()

    asyncio.run(exercise())

    assert len(updated) == 1
    assert updated[0][0] == job.scan_id
    assert updated[0][1]["status"] == "failed"
    assert updated[0][1]["risk_level"] == "INCONCLUSIVE"
    assert updated[0][1]["completed_at"]
    assert events == [(job.scan_id, "scan_cancelled")]
