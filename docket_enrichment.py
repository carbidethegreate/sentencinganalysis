from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from sqlalchemy import Table, select, update


TERMINAL_FAILURE_MESSAGE = "endpoint not yet implemented"


@dataclass(frozen=True)
class DocketJob:
    id: int
    case_id: int
    include_docket_text: bool
    status: str
    attempts: int


class DocketEnrichmentWorker:
    def __init__(
        self,
        engine,
        tables: Dict[str, Table],
        *,
        logger: Optional[Any] = None,
        now_fn: Callable[[], datetime] = None,
        endpoint_available: bool = False,
    ) -> None:
        self._engine = engine
        self._tables = tables
        self._logger = logger
        self._now = now_fn or datetime.utcnow
        self._endpoint_available = endpoint_available

    def run_once(self, max_jobs: int = 5) -> int:
        jobs = self._load_jobs(max_jobs)
        processed = 0
        for job in jobs:
            self._process_job(job)
            processed += 1
        return processed

    def _load_jobs(self, max_jobs: int) -> List[Dict[str, Any]]:
        job_table = self._tables["docket_enrichment_jobs"]
        with self._engine.begin() as conn:
            rows = (
                conn.execute(
                    select(job_table)
                    .where(job_table.c.status.in_(["queued", "running"]))
                    .order_by(job_table.c.created_at.asc(), job_table.c.id.asc())
                    .limit(max_jobs)
                )
                .mappings()
                .all()
            )
        return [dict(row) for row in rows]

    def _process_job(self, job: Dict[str, Any]) -> None:
        if job["status"] != "running":
            job = self._mark_running(job)

        if not self._endpoint_available:
            self._mark_failed(job, TERMINAL_FAILURE_MESSAGE)
            return

        # The real docket enrichment pipeline will be wired here later.
        self._mark_failed(job, TERMINAL_FAILURE_MESSAGE)

    def _mark_running(self, job: Dict[str, Any]) -> Dict[str, Any]:
        job_table = self._tables["docket_enrichment_jobs"]
        now = self._now()
        attempts = int(job.get("attempts") or 0) + 1
        updates = {
            "status": "running",
            "attempts": attempts,
            "started_at": now,
            "finished_at": None,
            "last_error": None,
        }
        with self._engine.begin() as conn:
            conn.execute(
                update(job_table)
                .where(job_table.c.id == job["id"])
                .values(**updates)
            )
        job.update(updates)
        return job

    def _mark_failed(self, job: Dict[str, Any], message: str) -> None:
        job_table = self._tables["docket_enrichment_jobs"]
        now = self._now()
        updates = {
            "status": "failed",
            "last_error": message,
            "finished_at": now,
        }
        with self._engine.begin() as conn:
            conn.execute(
                update(job_table)
                .where(job_table.c.id == job["id"])
                .values(**updates)
            )
        if self._logger:
            self._logger.warning(
                "Docket enrichment job %s failed: %s",
                job["id"],
                message,
            )
