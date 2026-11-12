"""Backup orchestration: transfer first, persist only on full success.

The ordering here is the core safety guarantee:

1. open an *attempt* row (short autocommit write, released immediately);
2. perform the entire AXFR over the network -- no database write lock is held;
3. only after the transfer is complete and TSIG-authenticated, open the single
   short write transaction that applies the RFC 1982 commit rule and replaces
   the stored version;
4. any failure (bad signature, truncated stream, timeout, commit rejection,
   process interruption between steps) leaves the previously stored version
   untouched;
5. record the outcome (including the failure reason) in the attempts table.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import axfr_client
from .config import Target
from .storage import CommitOutcome, CommitRejected, Storage


@dataclass
class JobView:
    job_id: str
    target_id: str
    label: str
    zone: str
    state: str  # running | success | failed
    started_at: str
    finished_at: str | None = None
    serial: int | None = None
    record_count: int | None = None
    message_count: int | None = None
    reason: str | None = None
    commit: CommitOutcome | None = None


class JobRegistry:
    """In-memory registry shared by the threads of one worker process."""

    def __init__(self, capacity: int = 50):
        self._jobs: dict[str, JobView] = {}
        self._order: list[str] = []
        self._capacity = capacity
        self._lock = threading.Lock()

    def create(self, target: Target) -> JobView:
        job = JobView(
            job_id=uuid.uuid4().hex,
            target_id=target.target_id,
            label=target.label,
            zone=target.zone,
            state="running",
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        with self._lock:
            self._jobs[job.job_id] = job
            self._order.append(job.job_id)
            for stale_id in self._order[: -self._capacity]:
                self._jobs.pop(stale_id, None)
            del self._order[: -self._capacity]
        return job

    def get(self, job_id: str) -> JobView | None:
        with self._lock:
            return self._jobs.get(job_id)

    def list_jobs(self) -> list[JobView]:
        with self._lock:
            return [self._jobs[jid] for jid in reversed(self._order)]

    def finish(
        self,
        job_id: str,
        *,
        state: str,
        reason: str | None,
        serial: int | None,
        record_count: int | None,
        message_count: int | None,
        commit: CommitOutcome | None,
    ) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            job.state = state
            job.reason = reason
            job.serial = serial
            job.record_count = record_count
            job.message_count = message_count
            job.commit = commit
            job.finished_at = datetime.now(timezone.utc).isoformat()


class BackupService:
    def __init__(self, storage: Storage, registry: JobRegistry):
        self.storage = storage
        self.registry = registry

    def run_backup(self, target: Target) -> JobView:
        job = self.registry.create(target)
        attempt_id = self.storage.record_attempt_start(target.zone)
        serial: int | None = None
        record_count: int | None = None
        message_count: int | None = None
        try:
            # All network I/O happens here, outside any DB write transaction.
            key = target.build_key()
            zone_data = axfr_client.axfr(
                target.host, target.port, target.zone, key
            )
            serial = zone_data.serial
            record_count = zone_data.record_count
            message_count = zone_data.message_count

            try:
                outcome = self.storage.commit_backup(
                    zone_data.origin,
                    zone_data.serial,
                    zone_data.rrs,
                    zone_data.message_count,
                )
            except CommitRejected as exc:
                self.storage.record_attempt_finish(
                    attempt_id, False, serial, record_count, exc.reason
                )
                self.registry.finish(
                    job.job_id,
                    state="failed",
                    reason=exc.reason,
                    serial=serial,
                    record_count=record_count,
                    message_count=message_count,
                    commit=None,
                )
                return self.registry.get(job.job_id)  # type: ignore[return-value]

            self.storage.record_attempt_finish(
                attempt_id, True, serial, record_count, outcome.reason
            )
            self.registry.finish(
                job.job_id,
                state="success",
                reason=outcome.reason,
                serial=serial,
                record_count=record_count,
                message_count=message_count,
                commit=outcome,
            )
        except axfr_client.TransferError as exc:
            reason = f"传输失败，已保留旧版：{exc}"
            self.storage.record_attempt_finish(
                attempt_id, False, serial, record_count, reason
            )
            self.registry.finish(
                job.job_id,
                state="failed",
                reason=reason,
                serial=serial,
                record_count=record_count,
                message_count=message_count,
                commit=None,
            )
        except Exception as exc:  # pragma: no cover - defensive catch-all
            reason = f"未预期错误，已保留旧版：{exc!r}"
            self.storage.record_attempt_finish(
                attempt_id, False, serial, record_count, reason
            )
            self.registry.finish(
                job.job_id,
                state="failed",
                reason=reason,
                serial=serial,
                record_count=record_count,
                message_count=message_count,
                commit=None,
            )
        return self.registry.get(job.job_id)  # type: ignore[return-value]
