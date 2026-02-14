from __future__ import annotations

import hashlib
import json
import random
import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from sqlalchemy import Table, case, func, insert, select, update
from sqlalchemy.exc import IntegrityError, ProgrammingError
from sqlalchemy.dialects.postgresql import insert as pg_insert

from pacer_http import PacerEnvironmentMismatch, TokenExpired
from pcl_client import PclApiError, PclClient

CRIMINAL_CASE_TYPES = {"cr", "crim", "ncrim", "dcrim"}
PCL_BATCH_CAP = 108000


def _to_naive_utc(value: Any) -> Any:
    if not isinstance(value, datetime):
        return value
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def _compact_error_text(value: Any, *, limit: int = 260) -> str:
    cleaned = str(value or "").strip()
    if not cleaned:
        return ""
    lowered = cleaned.lower()
    for needle in ("[sql:", "[parameters:", "(background on this error", "background on this error"):
        idx = lowered.find(needle)
        if idx > 0:
            cleaned = cleaned[:idx].strip()
            lowered = cleaned.lower()
    cleaned = re.sub(r"\s+", " ", cleaned)
    if len(cleaned) > limit:
        return cleaned[: limit - 3] + "..."
    return cleaned


def _extract_unique_constraint_name(exc: IntegrityError) -> Optional[str]:
    """Best-effort extraction of the Postgres unique constraint/index name."""

    orig = getattr(exc, "orig", None)
    diag = getattr(orig, "diag", None)
    constraint = getattr(diag, "constraint_name", None) if diag is not None else None
    if constraint:
        return str(constraint)
    rendered = str(orig or exc)
    match = re.search(r'unique constraint\\s+\"([^\"]+)\"', rendered, flags=re.IGNORECASE)
    if match:
        return match.group(1)
    return None


def _format_worker_exception(exc: Exception) -> str:
    if isinstance(exc, IntegrityError):
        constraint = _extract_unique_constraint_name(exc)
        if constraint:
            return f"worker exception: IntegrityError: duplicate key ({constraint})"
        details = _compact_error_text(getattr(exc, "orig", None) or exc)
        if details:
            return f"worker exception: IntegrityError: {details}"
        return "worker exception: IntegrityError"
    rendered = _compact_error_text(exc)
    if rendered:
        return f"worker exception: {type(exc).__name__}: {rendered}"
    return f"worker exception: {type(exc).__name__}"


@lru_cache(maxsize=1)
def _load_known_pcl_court_ids() -> set[str]:
    """Fallback list of PCL court IDs from Appendix A (data/pcl_courts.json).

    In some environments the `pcl_courts` table exists but hasn't been seeded yet.
    The batch worker still needs to validate (or at least not hard-fail) known IDs.
    """

    catalog_path = Path(__file__).resolve().parent / "data" / "pcl_courts.json"
    try:
        payload = json.loads(catalog_path.read_text(encoding="utf-8"))
    except Exception:
        return set()
    if not isinstance(payload, list):
        return set()
    ids: set[str] = set()
    for row in payload:
        if not isinstance(row, dict):
            continue
        if not bool(row.get("active", True)):
            continue
        court_id = str(row.get("pcl_court_id") or "").strip().lower()
        if court_id:
            ids.add(court_id)
    return ids


@dataclass
class PlannedSegment:
    date_filed_from: date
    date_filed_to: date


class PclBatchPlanner:
    def __init__(self, engine, tables: Dict[str, Table]) -> None:
        self._engine = engine
        self._tables = tables

    def create_batch_request(
        self,
        court_id: str,
        date_filed_from: date,
        date_filed_to: date,
        case_types: Sequence[str],
    ) -> int:
        filtered_case_types = self._filter_case_types(case_types)
        payload = json.dumps(filtered_case_types)
        with self._engine.begin() as conn:
            result = conn.execute(
                insert(self._tables["pcl_batch_requests"]).values(
                    court_id=court_id,
                    date_filed_from=date_filed_from,
                    date_filed_to=date_filed_to,
                    case_types=payload,
                    status="planned",
                )
            )
            batch_request_id = int(result.inserted_primary_key[0])
            segments = self._plan_segments(date_filed_from, date_filed_to)
            conn.execute(
                insert(self._tables["pcl_batch_segments"]),
                [
                    {
                        "batch_request_id": batch_request_id,
                        "court_id": court_id,
                        "date_filed_from": segment.date_filed_from,
                        "date_filed_to": segment.date_filed_to,
                        "segment_from": segment.date_filed_from,
                        "segment_to": segment.date_filed_to,
                        "case_types": payload,
                        "status": "queued",
                    }
                    for segment in segments
                ],
            )
        return batch_request_id

    def split_segment(
        self, segment_row: Dict[str, Any], *, reason: str
    ) -> List[int]:
        date_from: date = segment_row["date_filed_from"]
        date_to: date = segment_row["date_filed_to"]
        if date_from >= date_to:
            return []
        midpoint = date_from + timedelta(days=(date_to - date_from).days // 2)
        if midpoint < date_from:
            midpoint = date_from
        if midpoint >= date_to:
            return []
        segments = [
            PlannedSegment(date_from, midpoint),
            PlannedSegment(midpoint + timedelta(days=1), date_to),
        ]
        inserted_ids: List[int] = []
        with self._engine.begin() as conn:
            for segment in segments:
                result = conn.execute(
                    insert(self._tables["pcl_batch_segments"]).values(
                        batch_request_id=segment_row["batch_request_id"],
                        parent_segment_id=segment_row["id"],
                        court_id=segment_row["court_id"],
                        date_filed_from=segment.date_filed_from,
                        date_filed_to=segment.date_filed_to,
                        segment_from=segment.date_filed_from,
                        segment_to=segment.date_filed_to,
                        case_types=segment_row["case_types"],
                        status="queued",
                        error_message=reason,
                    )
                )
                inserted_ids.append(int(result.inserted_primary_key[0]))
            conn.execute(
                update(self._tables["pcl_batch_segments"])
                .where(self._tables["pcl_batch_segments"].c.id == segment_row["id"])
                .values(status="split", error_message=reason)
            )
        return inserted_ids

    def _plan_segments(self, date_from: date, date_to: date) -> List[PlannedSegment]:
        segments: List[PlannedSegment] = []
        current = date_from
        while current <= date_to:
            month_end = _last_day_of_month(current)
            if month_end > date_to:
                month_end = date_to
            segments.append(PlannedSegment(current, month_end))
            current = month_end + timedelta(days=1)
        return segments

    def _filter_case_types(self, case_types: Sequence[str]) -> List[str]:
        normalized = [case_type.lower().strip() for case_type in case_types if case_type]
        filtered = [case_type for case_type in normalized if case_type in CRIMINAL_CASE_TYPES]
        if not filtered:
            filtered = ["cr"]
        return sorted(set(filtered))


class PclBatchWorker:
    def __init__(
        self,
        engine,
        tables: Dict[str, Table],
        client: PclClient,
        *,
        logger: Optional[Any] = None,
        sleep_fn: Callable[[float], None] = None,
        now_fn: Callable[[], datetime] = None,
        max_concurrent_remote_jobs: int = 2,
        poll_base_seconds: float = 5.0,
        poll_jitter_seconds: float = 2.0,
        max_poll_attempts: int = 6,
        claim_timeout_minutes: int = 30,
    ) -> None:
        self._engine = engine
        self._tables = tables
        self._client = client
        self._logger = logger
        self._sleep = sleep_fn or (lambda seconds: None)
        self._now = now_fn or datetime.utcnow
        self._max_concurrent_remote_jobs = max(1, int(max_concurrent_remote_jobs))
        self._poll_base_seconds = poll_base_seconds
        self._poll_jitter_seconds = poll_jitter_seconds
        self._max_poll_attempts = max_poll_attempts
        self._claim_timeout_minutes = claim_timeout_minutes
        self._rng = random.Random()

    def _remote_in_flight_count(self) -> int:
        segment_table = self._tables["pcl_batch_segments"]
        in_flight_statuses = ["submitted", "running", "processing"]
        with self._engine.begin() as conn:
            value = conn.execute(
                select(func.count())
                .select_from(segment_table)
                .where(segment_table.c.status.in_(in_flight_statuses))
                .where(segment_table.c.report_id.isnot(None))
            ).scalar_one()
        return int(value or 0)

    def run_once(self, max_segments: int = 1, *, batch_request_id: Optional[int] = None) -> int:
        processed = 0
        segments = self._load_segments(max_segments, batch_request_id=batch_request_id)
        for segment in segments:
            try:
                self._process_segment(segment)
            except Exception as exc:
                # Never strand a claimed segment in "processing" due to an unexpected error.
                message = _format_worker_exception(exc)
                if self._logger:
                    self._logger.exception(
                        "Unexpected error while processing PCL batch segment %s",
                        segment.get("id"),
                    )
                self._mark_failed(segment, message)
            processed += 1
        return processed

    def _load_segments(
        self, max_segments: int, *, batch_request_id: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        segment_table = self._tables["pcl_batch_segments"]
        now = _to_naive_utc(self._now())
        pollable = segment_table.c.status.in_(["submitted", "running"]) & (
            (segment_table.c.next_poll_at.is_(None))
            | (segment_table.c.next_poll_at <= now)
        )
        queueable = (segment_table.c.status == "queued") & (
            (segment_table.c.next_poll_at.is_(None))
            | (segment_table.c.next_poll_at <= now)
        )
        allow_submit_new = True

        # Keep the number of remote batch jobs bounded globally (PCL enforces concurrency limits).
        if self._remote_in_flight_count() >= self._max_concurrent_remote_jobs:
            allow_submit_new = False  # only poll existing jobs until the in-flight count drops

        # Always poll in-flight jobs globally to avoid deadlocks where a scoped runner
        # can't free up the global concurrency slots it depends on. When a
        # `batch_request_id` is provided, only *submission* is scoped to that batch.
        where_clause = pollable
        if batch_request_id is None:
            if allow_submit_new:
                where_clause = where_clause | queueable
        else:
            if allow_submit_new:
                where_clause = where_clause | (
                    queueable & (segment_table.c.batch_request_id == batch_request_id)
                )

        # Poll due segments before submitting new queued segments.
        status_priority = case((segment_table.c.status == "queued", 1), else_=0)
        order_by_columns: List[Any] = []
        if batch_request_id is not None:
            # Prefer segments from the requested batch first so the UI-driven runner
            # makes visible progress, while still polling in-flight jobs globally.
            order_by_columns.append(
                case((segment_table.c.batch_request_id == batch_request_id, 0), else_=1).asc()
            )
        order_by_columns.extend(
            [
                status_priority.asc(),
                segment_table.c.next_poll_at.asc().nullsfirst(),
                segment_table.c.date_filed_to.desc().nullslast(),
                segment_table.c.id.asc(),
            ]
        )

        with self._engine.begin() as conn:
            if conn.dialect.name == "postgresql":
                stale_cutoff = now - timedelta(minutes=self._claim_timeout_minutes)
                claimable = where_clause
                reclaimable = (segment_table.c.status == "processing") & (
                    segment_table.c.updated_at < stale_cutoff
                )
                # Use transactional claiming to prevent two workers from processing
                # the same segment concurrently. Stale processing rows are reclaimed
                # so a crashed worker does not leave segments stuck forever.
                rows = (
                    conn.execute(
                        select(segment_table)
                        .where(claimable | reclaimable)
                        .order_by(*order_by_columns)
                        .limit(max_segments)
                        .with_for_update(skip_locked=True)
                    )
                    .mappings()
                    .all()
                )
            else:
                rows = (
                    conn.execute(
                        select(segment_table)
                        .where(where_clause)
                        .order_by(*order_by_columns)
                        .limit(max_segments)
                    )
                    .mappings()
                    .all()
                )
            if not rows:
                return []
            segment_ids = [row["id"] for row in rows]
            # Mark claimed rows as processing so other workers skip them outside
            # of the current transaction.
            conn.execute(
                update(segment_table)
                .where(segment_table.c.id.in_(segment_ids))
                .values(
                    status="processing",
                    updated_at=now,
                )
            )
            return [dict(row) for row in rows]

    def _process_segment(self, segment: Dict[str, Any]) -> None:
        status = segment["status"]
        if status == "processing":
            if segment.get("report_id"):
                self._poll_segment(segment)
            else:
                segment = self._submit_segment(segment)
            return
        if status == "queued":
            segment = self._submit_segment(segment)
        if segment["status"] in {"submitted", "running"}:
            self._poll_segment(segment)

    def _submit_segment(self, segment: Dict[str, Any]) -> Dict[str, Any]:
        # Double-check concurrency right before submission so a single run_once call
        # can't submit more jobs than allowed.
        if self._remote_in_flight_count() >= self._max_concurrent_remote_jobs:
            self._mark_deferred(segment, "waiting for a free batch slot")
            return segment

        if not self._court_id_is_valid(segment.get("court_id")):
            self._mark_failed(
                segment, "Court ID is not recognized. Please select a valid court."
            )
            return segment
        payload = self._build_payload(segment)
        try:
            response = self._client.start_case_download(payload)
        except PacerEnvironmentMismatch as exc:
            self._mark_failed(segment, str(exc))
            return segment
        except TokenExpired:
            self._mark_needs_reauth(segment)
            return segment
        except PclApiError as exc:
            if exc.status_code == 429 or _looks_like_pcl_concurrency_limit(exc.message):
                self._mark_throttled(segment, exc.message)
                return segment
            self._mark_failed(segment, exc.message)
            return segment
        report_id = response.get("reportId") or response.get("report_id")
        now = self._now()
        updates = {
            "status": "submitted",
            "report_id": report_id,
            "submitted_at": now,
            "search_payload_json": json.dumps(payload),
            "attempt_count": segment.get("attempt_count", 0) + 1,
        }
        self._update_segment(segment["id"], updates)
        segment.update(updates)
        return segment

    def _court_id_is_valid(self, court_id: Optional[str]) -> bool:
        if not court_id:
            return False
        normalized = str(court_id).strip().lower()
        table = self._tables.get("pcl_courts")
        if table is None:
            return True
        with self._engine.begin() as conn:
            row = conn.execute(
                select(table.c.pcl_court_id)
                .where(table.c.pcl_court_id == normalized)
                .where(table.c.active.is_(True))
            ).first()
        if row is not None:
            return True

        # Fallback: if DB is not seeded (or missing the entry), allow known IDs
        # from the local Appendix A catalog.
        known = _load_known_pcl_court_ids()
        if known:
            return normalized in known

        # If we can't validate at all, do not block the job: let the API tell us.
        return True

    def _poll_segment(self, segment: Dict[str, Any]) -> None:
        now = _to_naive_utc(self._now())
        next_poll_at = segment.get("next_poll_at")
        next_poll_at = _to_naive_utc(next_poll_at)
        if next_poll_at and isinstance(next_poll_at, datetime) and next_poll_at > now:
            # This segment was claimed too early (or time drifted). Put it back so it can be
            # claimed again when it is actually due.
            self._update_segment(segment["id"], {"status": segment["status"], "updated_at": now})
            return

        report_id = segment.get("report_id")
        if not report_id:
            self._mark_failed(segment, "missing report_id")
            return

        try:
            status_payload = self._client.get_case_download_status(report_id)
        except PacerEnvironmentMismatch as exc:
            self._handle_status_error(segment, str(exc))
            return
        except TokenExpired:
            self._mark_needs_reauth(segment)
            return
        except PclApiError as exc:
            self._handle_status_error(segment, exc.message)
            return

        remote_status = self._extract_status(status_payload)
        receipt = status_payload.get("receipt") or status_payload.get("receiptData")
        if receipt:
            self._persist_receipt(segment, report_id, receipt)

        if remote_status in {"completed", "complete", "done"}:
            self._download_and_ingest(segment)
            return
        if remote_status in {"error", "failed"}:
            message = self._extract_status_message(status_payload)
            self._handle_status_error(segment, message)
            return

        poll_attempts = segment.get("poll_attempts", 0) + 1
        delay = self._poll_base_seconds * (2 ** (poll_attempts - 1))
        delay += self._rng.uniform(0, self._poll_jitter_seconds)
        if poll_attempts >= self._max_poll_attempts:
            self._mark_failed(segment, "poll attempts exceeded")
            return
        self._update_segment(
            segment["id"],
            {
                "status": "running",
                "remote_status": remote_status,
                "poll_attempts": poll_attempts,
                "next_poll_at": now + timedelta(seconds=delay),
            },
        )
        # Do not sleep here: the scheduler/runner will pick this segment up again after `next_poll_at`.

    def _download_and_ingest(self, segment: Dict[str, Any]) -> None:
        report_id = segment["report_id"]
        try:
            payload = self._client.download_case_report(report_id)
        except TokenExpired:
            self._mark_needs_reauth(segment)
            return
        except PclApiError as exc:
            self._mark_failed(segment, exc.message)
            return

        records = _extract_case_records(payload)
        with self._engine.begin() as conn:
            for record in records:
                normalized = _normalize_case_record(record, segment["court_id"])
                if not normalized:
                    continue
                normalized["last_segment_id"] = segment["id"]
                record_hash = normalized["record_hash"]
                self._insert_raw_record(
                    conn,
                    segment,
                    report_id,
                    record_hash,
                    record,
                    normalized,
                )
                self._upsert_case(conn, normalized)

        delete_error = None
        try:
            self._client.delete_case_report(report_id)
        except PclApiError as exc:
            delete_error = exc.message
        except TokenExpired:
            delete_error = "needs re authorization"

        updates = {
            "status": "completed" if not delete_error else "completed_delete_failed",
            "completed_at": self._now(),
            "remote_status": "completed",
            "remote_status_message": delete_error,
        }
        self._update_segment(segment["id"], updates)

    def _insert_raw_record(
        self,
        conn,
        segment: Dict[str, Any],
        report_id: str,
        record_hash: str,
        payload_json: Dict[str, Any],
        normalized: Dict[str, Any],
    ) -> None:
        raw_table = self._tables["pcl_case_result_raw"]
        stmt_values = dict(
            segment_id=segment["id"],
            report_id=report_id,
            ingested_at=self._now(),
            court_id=normalized.get("court_id"),
            case_number=normalized.get("case_number"),
            record_hash=record_hash,
            payload_json=payload_json,
        )
        insert_stmt = insert(raw_table).values(**stmt_values)
        if conn.dialect.name == "postgresql":
            # SQLAlchemy's generic Insert doesn't support PG upsert helpers; use dialect insert.
            insert_stmt = pg_insert(raw_table).values(**stmt_values).on_conflict_do_nothing(
                index_elements=["record_hash"]
            )
        try:
            conn.execute(insert_stmt)
        except Exception:
            if conn.dialect.name != "sqlite":
                raise

    def _upsert_case(self, conn, normalized: Dict[str, Any]) -> None:
        case_table = self._tables["pcl_cases"]
        if conn.dialect.name == "postgresql":
            insert_stmt = pg_insert(case_table).values(**normalized)
            set_common = {
                "case_number": insert_stmt.excluded.case_number,
                "case_number_full": insert_stmt.excluded.case_number_full,
                "case_type": insert_stmt.excluded.case_type,
                "date_filed": insert_stmt.excluded.date_filed,
                "date_closed": insert_stmt.excluded.date_closed,
                "effective_date_closed": insert_stmt.excluded.effective_date_closed,
                "short_title": insert_stmt.excluded.short_title,
                "case_title": insert_stmt.excluded.case_title,
                "case_link": insert_stmt.excluded.case_link,
                "case_year": insert_stmt.excluded.case_year,
                "case_office": insert_stmt.excluded.case_office,
                "judge_last_name": insert_stmt.excluded.judge_last_name,
                "source_last_seen_at": insert_stmt.excluded.source_last_seen_at,
                "record_hash": insert_stmt.excluded.record_hash,
                "last_segment_id": insert_stmt.excluded.last_segment_id,
                "data_json": insert_stmt.excluded.data_json,
                "updated_at": datetime.utcnow(),
            }

            def _exec_with_savepoint(stmt) -> None:
                # Postgres aborts the entire transaction on any statement error.
                # A savepoint lets us recover and retry with an alternate conflict target.
                with conn.begin_nested():
                    conn.execute(stmt)

            def _upsert_by_case_id() -> None:
                stmt = insert_stmt.on_conflict_do_update(
                    index_elements=["court_id", "case_id"],
                    index_where=case_table.c.case_id.isnot(None),
                    set_=set_common,
                )
                try:
                    _exec_with_savepoint(stmt)
                except ProgrammingError:
                    # Some environments use a non-partial unique constraint/index.
                    stmt = insert_stmt.on_conflict_do_update(
                        index_elements=["court_id", "case_id"],
                        set_=set_common,
                    )
                    _exec_with_savepoint(stmt)

            def _upsert_by_case_number_full() -> None:
                # Never blank-out an existing case_id when the incoming record is missing it.
                set_with_case_id = dict(
                    set_common,
                    case_id=func.coalesce(insert_stmt.excluded.case_id, case_table.c.case_id),
                )
                stmt = insert_stmt.on_conflict_do_update(
                    index_elements=["court_id", "case_number_full"],
                    index_where=case_table.c.case_number_full.isnot(None),
                    set_=set_with_case_id,
                )
                try:
                    _exec_with_savepoint(stmt)
                except ProgrammingError:
                    # Some environments use a full unique constraint (non-partial).
                    stmt = insert_stmt.on_conflict_do_update(
                        index_elements=["court_id", "case_number_full"],
                        set_=set_with_case_id,
                    )
                    _exec_with_savepoint(stmt)

            case_id = normalized.get("case_id")
            try:
                if case_id:
                    _upsert_by_case_id()
                else:
                    _upsert_by_case_number_full()
            except IntegrityError as exc:
                constraint = _extract_unique_constraint_name(exc)
                # We can receive a different unique constraint violation than the conflict target.
                # Retry using the alternate unique key to merge the record.
                if constraint == "uq_pcl_cases_court_case_number_full":
                    _upsert_by_case_number_full()
                    return
                if constraint == "uq_pcl_cases_court_case_id" and case_id:
                    _upsert_by_case_id()
                    return
                raise
            return

        court_id = normalized["court_id"]
        case_id = normalized.get("case_id")
        case_number_full = normalized.get("case_number_full")

        existing = None
        if case_id:
            existing = conn.execute(
                select(case_table.c.id).where(
                    case_table.c.court_id == court_id, case_table.c.case_id == case_id
                )
            ).fetchone()
        if existing is None and case_number_full:
            existing = conn.execute(
                select(case_table.c.id).where(
                    case_table.c.court_id == court_id,
                    case_table.c.case_number_full == case_number_full,
                )
            ).fetchone()
        if existing:
            case_id_value = (
                case_id if case_id is not None else case_table.c.case_id
            )
            conn.execute(
                update(case_table)
                .where(case_table.c.id == existing.id)
                .values(
                    case_type=normalized["case_type"],
                    date_filed=normalized["date_filed"],
                    date_closed=normalized["date_closed"],
                    effective_date_closed=normalized["effective_date_closed"],
                    short_title=normalized["short_title"],
                    case_title=normalized["case_title"],
                    case_link=normalized["case_link"],
                    case_year=normalized["case_year"],
                    case_office=normalized["case_office"],
                    judge_last_name=normalized["judge_last_name"],
                    case_number=normalized["case_number"],
                    case_number_full=normalized["case_number_full"],
                    case_id=case_id_value,
                    source_last_seen_at=normalized["source_last_seen_at"],
                    record_hash=normalized["record_hash"],
                    last_segment_id=normalized["last_segment_id"],
                    data_json=normalized["data_json"],
                    updated_at=datetime.utcnow(),
                )
            )
            return

        try:
            conn.execute(insert(case_table).values(**normalized))
        except IntegrityError:
            # Another worker inserted concurrently. Retry as an update.
            existing = None
            if case_number_full:
                existing = conn.execute(
                    select(case_table.c.id).where(
                        case_table.c.court_id == court_id,
                        case_table.c.case_number_full == case_number_full,
                    )
                ).fetchone()
            if existing is None and case_id:
                existing = conn.execute(
                    select(case_table.c.id).where(
                        case_table.c.court_id == court_id, case_table.c.case_id == case_id
                    )
                ).fetchone()
            if not existing:
                raise
            case_id_value = case_id if case_id is not None else case_table.c.case_id
            conn.execute(
                update(case_table)
                .where(case_table.c.id == existing.id)
                .values(
                    case_type=normalized["case_type"],
                    date_filed=normalized["date_filed"],
                    date_closed=normalized["date_closed"],
                    effective_date_closed=normalized["effective_date_closed"],
                    short_title=normalized["short_title"],
                    case_title=normalized["case_title"],
                    case_link=normalized["case_link"],
                    case_year=normalized["case_year"],
                    case_office=normalized["case_office"],
                    judge_last_name=normalized["judge_last_name"],
                    case_number=normalized["case_number"],
                    case_number_full=normalized["case_number_full"],
                    case_id=case_id_value,
                    source_last_seen_at=normalized["source_last_seen_at"],
                    record_hash=normalized["record_hash"],
                    last_segment_id=normalized["last_segment_id"],
                    data_json=normalized["data_json"],
                    updated_at=datetime.utcnow(),
                )
            )

    def _persist_receipt(
        self, segment: Dict[str, Any], report_id: str, receipt: Dict[str, Any]
    ) -> None:
        receipt_table = self._tables["pcl_batch_receipts"]
        with self._engine.begin() as conn:
            conn.execute(
                insert(receipt_table).values(
                    segment_id=segment["id"],
                    report_id=report_id,
                    receipt_json=json.dumps(receipt),
                )
            )

    def _update_segment(self, segment_id: int, updates: Dict[str, Any]) -> None:
        segment_table = self._tables["pcl_batch_segments"]
        with self._engine.begin() as conn:
            conn.execute(
                update(segment_table)
                .where(segment_table.c.id == segment_id)
                .values(**updates)
            )

    def _mark_failed(self, segment: Dict[str, Any], message: str) -> None:
        if self._logger:
            self._logger.warning("PCL segment %s failed: %s", segment["id"], message)
        self._update_segment(
            segment["id"],
            {"status": "failed", "error_message": message, "remote_status_message": message},
        )

    def _mark_deferred(self, segment: Dict[str, Any], message: str) -> None:
        # Local throttling: delay submission a bit without counting as an API attempt.
        delay_seconds = 8 + self._rng.uniform(0, 6)
        now = self._now()
        if self._logger:
            self._logger.info(
                "Deferring PCL segment %s: %s (retry in %.0fs)",
                segment.get("id"),
                message,
                delay_seconds,
            )
        self._update_segment(
            segment["id"],
            {
                "status": "queued",
                "next_poll_at": now + timedelta(seconds=delay_seconds),
                "last_error": message,
                "updated_at": now,
            },
        )

    def _mark_throttled(self, segment: Dict[str, Any], message: str) -> None:
        # PCL can reject submissions when too many batch jobs are running.
        # Re-queue with backoff instead of permanently failing the segment.
        attempt = int(segment.get("attempt_count") or 0) + 1
        delay_seconds = min(900, 20 * (2 ** min(6, attempt - 1)))
        delay_seconds += self._rng.uniform(0, 10)
        now = self._now()
        if self._logger:
            self._logger.info(
                "PCL segment %s throttled (429); re-queueing in %.0fs",
                segment.get("id"),
                delay_seconds,
            )
        self._update_segment(
            segment["id"],
            {
                "status": "queued",
                "attempt_count": attempt,
                "next_poll_at": now + timedelta(seconds=delay_seconds),
                "last_error": message,
                "error_message": message,
                "remote_status_message": message,
                "updated_at": now,
            },
        )

    def _mark_needs_reauth(self, segment: Dict[str, Any]) -> None:
        self._update_segment(
            segment["id"],
            {
                "status": "failed",
                "error_message": "needs re authorization",
                "remote_status_message": "needs re authorization",
            },
        )

    def _handle_status_error(self, segment: Dict[str, Any], message: str) -> None:
        if _looks_like_too_many_results(message):
            planner = PclBatchPlanner(self._engine, self._tables)
            inserted_ids = planner.split_segment(segment, reason=message)
            if not inserted_ids:
                # If the segment is already at the smallest possible range,
                # fail it to avoid an infinite retry loop.
                self._mark_failed(
                    segment,
                    "Segment cannot be split further; marking failed to avoid retry loop.",
                )
            return
        self._mark_failed(segment, message)

    def _build_payload(self, segment: Dict[str, Any]) -> Dict[str, Any]:
        case_types = json.loads(segment["case_types"])
        payload = {
            "courtId": [segment["court_id"]],
            "caseType": case_types,
            "dateFiledFrom": segment["date_filed_from"].isoformat(),
            "dateFiledTo": segment["date_filed_to"].isoformat(),
        }
        return payload

    def _extract_status(self, payload: Dict[str, Any]) -> str:
        status = (
            payload.get("status")
            or payload.get("reportStatus")
            or payload.get("report_status")
            or ""
        )
        return str(status).strip().lower()

    def _extract_status_message(self, payload: Dict[str, Any]) -> str:
        for key in ("message", "error", "statusMessage"):
            value = payload.get(key)
            if value is None:
                continue
            rendered = str(value).strip()
            if not rendered:
                continue
            if rendered.lower() == "none":
                continue
            return rendered
        return "unknown error"


def _extract_case_records(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    if "content" in payload:
        value = payload.get("content")
        if isinstance(value, list):
            return value
        return []
    for key in ("cases", "caseList", "caseResults", "results", "data"):
        if key in payload and isinstance(payload.get(key), list):
            return payload[key]
    if "case" in payload and isinstance(payload.get("case"), list):
        return payload["case"]
    return []


def _looks_like_pcl_concurrency_limit(message: str) -> bool:
    lowered = (message or "").strip().lower()
    if not lowered:
        return False
    return "exceeded maximum batch jobs" in lowered or "running concurrently" in lowered


def _record_hash(record: Dict[str, Any]) -> str:
    raw = json.dumps(record, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _normalize_case_record(record: Dict[str, Any], default_court_id: str) -> Dict[str, Any]:
    case_number = (
        record.get("caseNumber")
        or record.get("case_number")
        or record.get("cs_case_number")
    )
    if not case_number:
        return {}
    court_id = record.get("courtId") or record.get("court_id") or default_court_id
    date_filed = _parse_date(record.get("dateFiled") or record.get("date_filed"))
    date_closed = _parse_date(record.get("dateClosed") or record.get("date_closed"))
    case_type_raw = record.get("caseType") or record.get("case_type")
    case_type = str(case_type_raw).strip().lower() if case_type_raw else None
    if case_type and case_type not in CRIMINAL_CASE_TYPES:
        return {}
    short_title = (
        record.get("shortTitle")
        or record.get("short_title")
        or record.get("cs_short_title")
    )
    case_title = (
        record.get("caseTitle")
        or record.get("case_title")
        or record.get("title")
        or record.get("cs_case_title")
    )
    case_number_full = (
        record.get("caseNumberFull")
        or record.get("case_number_full")
        or record.get("fullCaseNumber")
        or case_number
    )
    if isinstance(case_number_full, str) and not case_number_full.strip():
        case_number_full = case_number
    case_id = record.get("caseId") or record.get("case_id")
    case_link = record.get("caseLink") or record.get("case_link")
    effective_date_closed = _parse_date(
        record.get("effectiveDateClosed") or record.get("effective_date_closed")
    )
    case_year = record.get("caseYear") or record.get("case_year")
    case_office = record.get("caseOffice") or record.get("case_office")
    if not case_year or not case_office:
        parsed_office, parsed_year, _ = _parse_case_number_parts(case_number_full)
        case_office = case_office or parsed_office
        case_year = case_year or parsed_year
    judge_last_name = _normalize_judge_last_name(
        record.get("judgeLastName")
        or record.get("judge_last_name")
        or record.get("assignedTo")
        or record.get("assigned_to")
    )
    record_hash = _record_hash(record)
    return {
        "court_id": court_id,
        "case_number": str(case_number),
        "case_number_full": str(case_number_full),
        "case_type": case_type,
        "date_filed": date_filed,
        "date_closed": date_closed,
        "effective_date_closed": effective_date_closed,
        "short_title": short_title,
        "case_title": case_title,
        "case_link": case_link,
        "case_year": str(case_year) if case_year is not None else None,
        "case_office": str(case_office) if case_office is not None else None,
        "judge_last_name": judge_last_name,
        "case_id": str(case_id) if case_id else None,
        "source_last_seen_at": datetime.utcnow(),
        "record_hash": record_hash,
        "last_segment_id": None,
        "data_json": json.dumps(record, sort_keys=True, default=str),
    }


def _parse_case_number_parts(case_number: Any) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    if not isinstance(case_number, str):
        return None, None, None
    cleaned = case_number.strip()
    if not cleaned:
        return None, None, None
    match = re.match(
        r"^(?P<office>\d+):(?P<year>\d{2,4})-[A-Za-z]+-(?P<number>\d+)",
        cleaned,
    )
    if not match:
        return None, None, None
    return match.group("office"), match.group("year"), match.group("number")


def _parse_date(value: Any) -> Optional[date]:
    if isinstance(value, date):
        return value
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return None
        try:
            return datetime.fromisoformat(value).date()
        except ValueError:
            try:
                return datetime.strptime(value, "%Y-%m-%d").date()
            except ValueError:
                return None
    return None


def _normalize_judge_last_name(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    # Handle "Last, First ..." formats.
    if "," in cleaned:
        left = cleaned.split(",", 1)[0].strip()
        left = left.strip(",.")
        if left:
            return left
    tokens = [token for token in re.split(r"\s+", cleaned) if token]
    if not tokens:
        return None
    last = tokens[-1].strip(",.")
    return last or None


def _looks_like_too_many_results(message: str) -> bool:
    if not message:
        return False
    message_lower = message.lower()
    if "too many" in message_lower or "exceeds" in message_lower:
        return True
    if str(PCL_BATCH_CAP) in message_lower:
        return True
    return bool(re.search(r"exceed(s|ed).+result", message_lower))


def _last_day_of_month(current: date) -> date:
    if current.month == 12:
        return date(current.year, 12, 31)
    first_next_month = date(current.year, current.month + 1, 1)
    return first_next_month - timedelta(days=1)
