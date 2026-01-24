from __future__ import annotations

import hashlib
import json
import random
import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from sqlalchemy import Table, insert, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from pacer_http import TokenExpired
from pcl_client import PclApiError, PclClient

CRIMINAL_CASE_TYPES = {"cr", "crim", "ncrim", "dcrim"}
PCL_BATCH_CAP = 108000


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
        poll_base_seconds: float = 5.0,
        poll_jitter_seconds: float = 2.0,
        max_poll_attempts: int = 6,
    ) -> None:
        self._engine = engine
        self._tables = tables
        self._client = client
        self._logger = logger
        self._sleep = sleep_fn or (lambda seconds: None)
        self._now = now_fn or datetime.utcnow
        self._poll_base_seconds = poll_base_seconds
        self._poll_jitter_seconds = poll_jitter_seconds
        self._max_poll_attempts = max_poll_attempts
        self._rng = random.Random()

    def run_once(self, max_segments: int = 1) -> int:
        processed = 0
        segments = self._load_segments(max_segments)
        for segment in segments:
            self._process_segment(segment)
            processed += 1
        return processed

    def _load_segments(self, max_segments: int) -> List[Dict[str, Any]]:
        segments: List[Dict[str, Any]] = []
        segment_table = self._tables["pcl_batch_segments"]
        with self._engine.begin() as conn:
            rows = (
                conn.execute(
                    select(segment_table)
                    .where(
                        segment_table.c.status.in_(
                            ["queued", "submitted", "running"]
                        )
                    )
                    .order_by(segment_table.c.created_at.asc())
                    .limit(max_segments)
                )
                .mappings()
                .all()
            )
            segments.extend(dict(row) for row in rows)
        return segments

    def _process_segment(self, segment: Dict[str, Any]) -> None:
        status = segment["status"]
        if status == "queued":
            segment = self._submit_segment(segment)
        if segment["status"] in {"submitted", "running"}:
            self._poll_segment(segment)

    def _submit_segment(self, segment: Dict[str, Any]) -> Dict[str, Any]:
        payload = self._build_payload(segment)
        try:
            response = self._client.start_case_download(payload)
        except TokenExpired:
            self._mark_needs_reauth(segment)
            return segment
        except PclApiError as exc:
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

    def _poll_segment(self, segment: Dict[str, Any]) -> None:
        now = self._now()
        next_poll_at = segment.get("next_poll_at")
        if next_poll_at and isinstance(next_poll_at, datetime) and next_poll_at > now:
            return

        report_id = segment.get("report_id")
        if not report_id:
            self._mark_failed(segment, "missing report_id")
            return

        try:
            status_payload = self._client.get_case_download_status(report_id)
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
        self._sleep(delay)

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
        insert_stmt = insert(raw_table).values(
            segment_id=segment["id"],
            report_id=report_id,
            ingested_at=self._now(),
            court_id=normalized.get("court_id"),
            case_number=normalized.get("case_number"),
            record_hash=record_hash,
            payload_json=payload_json,
        )
        if conn.dialect.name == "postgresql":
            insert_stmt = insert_stmt.on_conflict_do_nothing(
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
            stmt = pg_insert(case_table).values(**normalized)
            stmt = stmt.on_conflict_do_update(
                index_elements=["court_id", "case_number"],
                set_={
                    "case_number_full": stmt.excluded.case_number_full,
                    "case_type": stmt.excluded.case_type,
                    "date_filed": stmt.excluded.date_filed,
                    "date_closed": stmt.excluded.date_closed,
                    "effective_date_closed": stmt.excluded.effective_date_closed,
                    "short_title": stmt.excluded.short_title,
                    "case_title": stmt.excluded.case_title,
                    "case_link": stmt.excluded.case_link,
                    "case_year": stmt.excluded.case_year,
                    "case_office": stmt.excluded.case_office,
                    "judge_last_name": stmt.excluded.judge_last_name,
                    "case_id": stmt.excluded.case_id,
                    "source_last_seen_at": stmt.excluded.source_last_seen_at,
                    "record_hash": stmt.excluded.record_hash,
                    "last_segment_id": stmt.excluded.last_segment_id,
                    "data_json": stmt.excluded.data_json,
                    "updated_at": datetime.utcnow(),
                },
            )
            conn.execute(stmt)
            return
        existing = conn.execute(
            select(case_table.c.id).where(
                case_table.c.court_id == normalized["court_id"],
                case_table.c.case_number == normalized["case_number"],
            )
        ).fetchone()
        if existing:
            conn.execute(
                update(case_table)
                .where(case_table.c.id == existing.id)
                .values(
                    case_number_full=normalized["case_number_full"],
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
                    case_id=normalized["case_id"],
                    source_last_seen_at=normalized["source_last_seen_at"],
                    record_hash=normalized["record_hash"],
                    last_segment_id=normalized["last_segment_id"],
                    data_json=normalized["data_json"],
                    updated_at=datetime.utcnow(),
                )
            )
        else:
            conn.execute(insert(case_table).values(**normalized))

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
            planner.split_segment(segment, reason=message)
            return
        self._mark_failed(segment, message)

    def _build_payload(self, segment: Dict[str, Any]) -> Dict[str, Any]:
        case_types = json.loads(segment["case_types"])
        payload = {
            "courtId": segment["court_id"],
            "caseTypes": case_types,
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
        return (
            str(payload.get("message"))
            or str(payload.get("error"))
            or str(payload.get("statusMessage"))
            or "unknown error"
        )


def _extract_case_records(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    for key in ("cases", "caseList", "caseResults", "results", "data"):
        value = payload.get(key)
        if isinstance(value, list):
            return value
    if isinstance(payload.get("case"), list):
        return payload["case"]
    return []


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
    case_id = record.get("caseId") or record.get("case_id")
    case_link = record.get("caseLink") or record.get("case_link")
    effective_date_closed = _parse_date(
        record.get("effectiveDateClosed") or record.get("effective_date_closed")
    )
    case_office, case_year, _ = _parse_case_number_parts(case_number_full)
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
        "case_year": case_year,
        "case_office": case_office,
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
    match = re.match(r"^(?P<office>\\d+):(?P<year>\\d{2,4})-[a-z]+-(?P<number>\\d+)", cleaned)
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
