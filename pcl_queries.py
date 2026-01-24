from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple

from sqlalchemy import and_, func, or_, select


DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = 100


@dataclass(frozen=True)
class PclCaseFilters:
    court_id: str = ""
    date_filed_from: Optional[date] = None
    date_filed_to: Optional[date] = None
    case_type: str = ""
    judge_last_name: str = ""
    indexed_only: bool = False
    enriched_only: bool = False
    sentencing_only: bool = False
    search_text: str = ""


@dataclass(frozen=True)
class Pagination:
    page: int
    page_size: int
    total: int

    @property
    def total_pages(self) -> int:
        if self.total <= 0:
            return 1
        return max(1, (self.total + self.page_size - 1) // self.page_size)


@dataclass(frozen=True)
class PclCaseListResult:
    rows: List[Dict[str, Any]]
    pagination: Pagination
    available_courts: Sequence[str]
    available_case_types: Sequence[str]


def parse_filters(args: Dict[str, str]) -> Tuple[PclCaseFilters, int, int]:
    court_id = (args.get("court_id") or "").strip().lower()
    case_type = (args.get("case_type") or "").strip().lower()
    judge_last_name = (args.get("judge_last_name") or "").strip()
    search_text = (args.get("q") or "").strip()

    date_from = _parse_date(args.get("date_filed_from"))
    date_to = _parse_date(args.get("date_filed_to"))
    if date_from and date_to and date_from > date_to:
        date_from, date_to = date_to, date_from

    indexed_only = _parse_bool(args.get("indexed_only"))
    enriched_only = _parse_bool(args.get("enriched_only"))
    sentencing_only = _parse_bool(args.get("sentencing_only"))

    page = _parse_int(args.get("page"), default=1, minimum=1)
    page_size = _parse_int(args.get("page_size"), default=DEFAULT_PAGE_SIZE, minimum=1)
    page_size = min(page_size, MAX_PAGE_SIZE)

    filters = PclCaseFilters(
        court_id=court_id,
        date_filed_from=date_from,
        date_filed_to=date_to,
        case_type=case_type,
        judge_last_name=judge_last_name,
        indexed_only=indexed_only,
        enriched_only=enriched_only,
        sentencing_only=sentencing_only,
        search_text=search_text,
    )
    return filters, page, page_size


def list_cases(engine, tables, filters: PclCaseFilters, *, page: int, page_size: int) -> PclCaseListResult:
    pcl_cases = tables["pcl_cases"]
    pcl_batch_segments = tables["pcl_batch_segments"]

    where_clauses = _build_where_clauses(pcl_cases, filters)

    base_stmt = (
        select(
            pcl_cases.c.id,
            pcl_cases.c.court_id,
            pcl_cases.c.case_number,
            pcl_cases.c.case_number_full,
            pcl_cases.c.case_type,
            pcl_cases.c.date_filed,
            pcl_cases.c.date_closed,
            pcl_cases.c.short_title,
            pcl_cases.c.case_title,
            pcl_cases.c.judge_last_name,
            pcl_cases.c.last_segment_id,
            pcl_batch_segments.c.status.label("segment_status"),
            pcl_batch_segments.c.date_filed_from.label("segment_date_from"),
            pcl_batch_segments.c.date_filed_to.label("segment_date_to"),
            pcl_batch_segments.c.completed_at.label("segment_completed_at"),
        )
        .select_from(
            pcl_cases.outerjoin(
                pcl_batch_segments, pcl_batch_segments.c.id == pcl_cases.c.last_segment_id
            )
        )
        .where(and_(*where_clauses))
        .order_by(pcl_cases.c.date_filed.desc().nullslast(), pcl_cases.c.id.desc())
    )

    count_stmt = select(func.count()).select_from(pcl_cases).where(and_(*where_clauses))

    offset = (page - 1) * page_size
    paged_stmt = base_stmt.limit(page_size).offset(offset)

    with engine.begin() as conn:
        total = int(conn.execute(count_stmt).scalar_one())
        rows = conn.execute(paged_stmt).mappings().all()
        available_courts = _load_distinct(conn, pcl_cases.c.court_id)
        available_case_types = _load_distinct(conn, pcl_cases.c.case_type)

    pagination = Pagination(page=page, page_size=page_size, total=total)
    return PclCaseListResult(
        rows=[dict(row) for row in rows],
        pagination=pagination,
        available_courts=available_courts,
        available_case_types=available_case_types,
    )


def get_case_detail(engine, tables, case_id: int) -> Optional[Dict[str, Any]]:
    pcl_cases = tables["pcl_cases"]
    pcl_batch_segments = tables["pcl_batch_segments"]

    stmt = (
        select(
            pcl_cases,
            pcl_batch_segments.c.status.label("segment_status"),
            pcl_batch_segments.c.date_filed_from.label("segment_date_from"),
            pcl_batch_segments.c.date_filed_to.label("segment_date_to"),
            pcl_batch_segments.c.report_id.label("segment_report_id"),
            pcl_batch_segments.c.remote_status.label("segment_remote_status"),
            pcl_batch_segments.c.remote_status_message.label("segment_remote_status_message"),
            pcl_batch_segments.c.submitted_at.label("segment_submitted_at"),
            pcl_batch_segments.c.completed_at.label("segment_completed_at"),
        )
        .select_from(
            pcl_cases.outerjoin(
                pcl_batch_segments, pcl_batch_segments.c.id == pcl_cases.c.last_segment_id
            )
        )
        .where(pcl_cases.c.id == case_id)
        .limit(1)
    )

    with engine.begin() as conn:
        row = conn.execute(stmt).mappings().first()
        if not row:
            return None
        detail = dict(row)
        raw_payloads = _load_raw_payloads(conn, tables, detail)
        receipts = _load_receipts(conn, tables, detail)

    detail["raw_payloads"] = raw_payloads
    detail["receipts"] = receipts
    return detail


def _build_where_clauses(pcl_cases, filters: PclCaseFilters) -> List[Any]:
    clauses: List[Any] = [pcl_cases.c.id.is_not(None)]
    if filters.court_id:
        clauses.append(pcl_cases.c.court_id == filters.court_id)
    if filters.case_type:
        clauses.append(pcl_cases.c.case_type == filters.case_type)
    if filters.judge_last_name:
        clauses.append(func.lower(pcl_cases.c.judge_last_name) == filters.judge_last_name.lower())
    if filters.date_filed_from:
        clauses.append(pcl_cases.c.date_filed >= filters.date_filed_from)
    if filters.date_filed_to:
        clauses.append(pcl_cases.c.date_filed <= filters.date_filed_to)
    if filters.search_text:
        like_pattern = f"%{filters.search_text.lower()}%"
        clauses.append(
            or_(
                func.lower(pcl_cases.c.case_number).like(like_pattern),
                func.lower(pcl_cases.c.case_number_full).like(like_pattern),
                func.lower(pcl_cases.c.short_title).like(like_pattern),
                func.lower(pcl_cases.c.case_title).like(like_pattern),
            )
        )
    if filters.indexed_only:
        clauses.append(pcl_cases.c.record_hash.is_not(None))
    # Enrichment flags are not yet modeled; keep filters as no-ops.
    return clauses


def _load_raw_payloads(conn, tables, detail: Dict[str, Any]) -> List[Dict[str, Any]]:
    pcl_case_result_raw = tables["pcl_case_result_raw"]
    case_number = detail.get("case_number")
    court_id = detail.get("court_id")
    if not case_number or not court_id:
        return []
    stmt = (
        select(
            pcl_case_result_raw.c.id,
            pcl_case_result_raw.c.created_at,
            pcl_case_result_raw.c.segment_id,
            pcl_case_result_raw.c.report_id,
            pcl_case_result_raw.c.record_hash,
            pcl_case_result_raw.c.payload_json,
        )
        .where(
            pcl_case_result_raw.c.case_number == case_number,
            pcl_case_result_raw.c.court_id == court_id,
        )
        .order_by(pcl_case_result_raw.c.created_at.desc(), pcl_case_result_raw.c.id.desc())
        .limit(25)
    )
    return [dict(row) for row in conn.execute(stmt).mappings().all()]


def _load_receipts(conn, tables, detail: Dict[str, Any]) -> List[Dict[str, Any]]:
    pcl_batch_receipts = tables["pcl_batch_receipts"]
    last_segment_id = detail.get("last_segment_id")
    if not last_segment_id:
        return []
    stmt = (
        select(
            pcl_batch_receipts.c.id,
            pcl_batch_receipts.c.created_at,
            pcl_batch_receipts.c.segment_id,
            pcl_batch_receipts.c.report_id,
            pcl_batch_receipts.c.receipt_json,
        )
        .where(pcl_batch_receipts.c.segment_id == last_segment_id)
        .order_by(pcl_batch_receipts.c.created_at.desc(), pcl_batch_receipts.c.id.desc())
        .limit(10)
    )
    return [dict(row) for row in conn.execute(stmt).mappings().all()]


def _load_distinct(conn, column) -> List[str]:
    stmt = select(column).where(column.is_not(None)).group_by(column).order_by(column.asc())
    return [row[0] for row in conn.execute(stmt).all() if row[0]]


def _parse_date(value: Optional[str]) -> Optional[date]:
    if not value:
        return None
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


def _parse_bool(value: Optional[str]) -> bool:
    if not value:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _parse_int(value: Optional[str], *, default: int, minimum: int) -> int:
    if not value:
        return default
    try:
        parsed = int(value)
    except ValueError:
        return default
    return max(minimum, parsed)
