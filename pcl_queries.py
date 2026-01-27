from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple

from sqlalchemy import and_, desc, exists, func, inspect, literal, or_, select

from sentencing_queries import has_sentencing_event_clause


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
    field_name: str = ""
    field_value: str = ""


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


@dataclass(frozen=True)
class PclCaseCardResult:
    rows: List[Dict[str, Any]]
    pagination: Pagination


def parse_filters(args: Dict[str, str]) -> Tuple[PclCaseFilters, int, int]:
    court_id = (args.get("court_id") or "").strip().lower()
    case_type = (args.get("case_type") or "").strip().lower()
    judge_last_name = (args.get("judge_last_name") or "").strip()
    search_text = (args.get("q") or "").strip()
    field_name = (args.get("field_name") or "").strip()
    field_value = (args.get("field_value") or "").strip()

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
        field_name=field_name,
        field_value=field_value,
    )
    return filters, page, page_size


def list_cases(engine, tables, filters: PclCaseFilters, *, page: int, page_size: int) -> PclCaseListResult:
    pcl_cases = tables["pcl_cases"]
    pcl_batch_segments = tables["pcl_batch_segments"]
    docket_enrichment_jobs = _maybe_table(engine, tables, "docket_enrichment_jobs")
    case_fields = _maybe_table(engine, tables, "pcl_case_fields")

    where_clauses = _build_where_clauses(pcl_cases, filters, case_fields=case_fields)
    enrichment_status = literal(None).label("enrichment_status")
    enrichment_updated_at = literal(None).label("enrichment_updated_at")
    has_enrichment = None
    if docket_enrichment_jobs is not None:
        enrichment_status = (
            select(docket_enrichment_jobs.c.status)
            .where(docket_enrichment_jobs.c.case_id == pcl_cases.c.id)
            .order_by(
                docket_enrichment_jobs.c.created_at.desc(),
                docket_enrichment_jobs.c.id.desc(),
            )
            .limit(1)
            .scalar_subquery()
            .label("enrichment_status")
        )
        enrichment_updated_at = (
            select(docket_enrichment_jobs.c.updated_at)
            .where(docket_enrichment_jobs.c.case_id == pcl_cases.c.id)
            .order_by(
                docket_enrichment_jobs.c.created_at.desc(),
                docket_enrichment_jobs.c.id.desc(),
            )
            .limit(1)
            .scalar_subquery()
            .label("enrichment_updated_at")
        )
        has_enrichment = exists(
            select(1).where(docket_enrichment_jobs.c.case_id == pcl_cases.c.id)
        )

    has_sentencing = literal(False).label("has_sentencing")
    sentencing_events = _maybe_table(engine, tables, "sentencing_events")
    if sentencing_events is not None:
        has_sentencing = exists(
            has_sentencing_event_clause(pcl_cases, sentencing_events)
        ).label("has_sentencing")

    base_stmt = (
        select(
            pcl_cases.c.id,
            pcl_cases.c.court_id,
            pcl_cases.c.case_number,
            pcl_cases.c.case_number_full,
            pcl_cases.c.case_type,
            pcl_cases.c.date_filed,
            pcl_cases.c.date_closed,
            pcl_cases.c.effective_date_closed,
            pcl_cases.c.short_title,
            pcl_cases.c.case_title,
            pcl_cases.c.judge_last_name,
            pcl_cases.c.last_search_run_id,
            pcl_cases.c.last_search_run_at,
            enrichment_status,
            enrichment_updated_at,
            has_sentencing,
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


def list_case_cards(
    engine, tables, filters: PclCaseFilters, *, page: int, page_size: int
) -> PclCaseCardResult:
    pcl_cases = tables["pcl_cases"]
    docket_enrichment_jobs = _maybe_table(engine, tables, "docket_enrichment_jobs")
    case_fields = _maybe_table(engine, tables, "pcl_case_fields")
    where_clauses = _build_where_clauses(pcl_cases, filters, case_fields=case_fields)
    enrichment_status = literal(None).label("enrichment_status")
    enrichment_updated_at = literal(None).label("enrichment_updated_at")
    if docket_enrichment_jobs is not None:
        enrichment_status = (
            select(docket_enrichment_jobs.c.status)
            .where(docket_enrichment_jobs.c.case_id == pcl_cases.c.id)
            .order_by(
                docket_enrichment_jobs.c.created_at.desc(),
                docket_enrichment_jobs.c.id.desc(),
            )
            .limit(1)
            .scalar_subquery()
            .label("enrichment_status")
        )
        enrichment_updated_at = (
            select(docket_enrichment_jobs.c.updated_at)
            .where(docket_enrichment_jobs.c.case_id == pcl_cases.c.id)
            .order_by(
                docket_enrichment_jobs.c.created_at.desc(),
                docket_enrichment_jobs.c.id.desc(),
            )
            .limit(1)
            .scalar_subquery()
            .label("enrichment_updated_at")
        )

    has_sentencing = literal(False).label("has_sentencing")
    sentencing_events = _maybe_table(engine, tables, "sentencing_events")
    if sentencing_events is not None:
        has_sentencing = exists(
            has_sentencing_event_clause(pcl_cases, sentencing_events)
        ).label("has_sentencing")

    base_stmt = (
        select(
            pcl_cases.c.id,
            pcl_cases.c.court_id,
            pcl_cases.c.case_number,
            pcl_cases.c.case_number_full,
            pcl_cases.c.case_title,
            pcl_cases.c.case_type,
            pcl_cases.c.date_filed,
            pcl_cases.c.judge_last_name,
            pcl_cases.c.case_year,
            pcl_cases.c.case_office,
            pcl_cases.c.case_link,
            pcl_cases.c.last_search_run_id,
            pcl_cases.c.last_search_run_at,
            enrichment_status,
            enrichment_updated_at,
            has_sentencing,
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

    pagination = Pagination(page=page, page_size=page_size, total=total)
    return PclCaseCardResult(rows=[dict(row) for row in rows], pagination=pagination)


def get_case_detail(engine, tables, case_id: int) -> Optional[Dict[str, Any]]:
    pcl_cases = tables["pcl_cases"]
    pcl_batch_segments = tables["pcl_batch_segments"]
    pacer_search_runs = tables["pacer_search_runs"]

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
            pacer_search_runs.c.id.label("pacer_run_id"),
            pacer_search_runs.c.created_at.label("pacer_run_created_at"),
            pacer_search_runs.c.search_type.label("pacer_run_search_type"),
            pacer_search_runs.c.search_mode.label("pacer_run_search_mode"),
            pacer_search_runs.c.report_id.label("pacer_run_report_id"),
            pacer_search_runs.c.report_status.label("pacer_run_report_status"),
            pacer_search_runs.c.cases_inserted.label("pacer_run_cases_inserted"),
            pacer_search_runs.c.cases_updated.label("pacer_run_cases_updated"),
            pacer_search_runs.c.parties_inserted.label("pacer_run_parties_inserted"),
            pacer_search_runs.c.parties_updated.label("pacer_run_parties_updated"),
            pacer_search_runs.c.receipt_json.label("pacer_run_receipt_json"),
        )
        .select_from(
            pcl_cases.outerjoin(
                pcl_batch_segments, pcl_batch_segments.c.id == pcl_cases.c.last_segment_id
            ).outerjoin(
                pacer_search_runs,
                pacer_search_runs.c.id == pcl_cases.c.last_search_run_id,
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
        case_fields = _load_case_fields(conn, tables, detail)
        docket_jobs = _load_docket_jobs(conn, tables, detail)
        docket_estimate = _estimate_docket_cost(conn, tables, detail)
        document_jobs = _load_document_jobs(conn, tables, detail)
        sentencing_detail = _load_sentencing_detail(conn, tables, detail)

    detail["raw_payloads"] = raw_payloads
    detail["receipts"] = receipts
    detail["case_fields"] = case_fields
    detail["docket_jobs"] = docket_jobs
    detail["docket_estimate"] = docket_estimate
    detail["document_jobs"] = document_jobs
    detail.update(sentencing_detail)
    return detail


def _build_where_clauses(
    pcl_cases, filters: PclCaseFilters, *, case_fields=None
) -> List[Any]:
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
    if (filters.field_name or filters.field_value) and case_fields is not None:
        field_clauses = [case_fields.c.case_id == pcl_cases.c.id]
        if filters.field_name:
            field_clauses.append(
                func.lower(case_fields.c.field_name) == filters.field_name.lower()
            )
        if filters.field_value:
            field_like = f"%{filters.field_value.lower()}%"
            field_clauses.append(
                func.lower(case_fields.c.field_value_text).like(field_like)
            )
        clauses.append(exists(select(1).where(and_(*field_clauses))))
    if filters.indexed_only:
        clauses.append(pcl_cases.c.record_hash.is_not(None))
    if filters.enriched_only and "docket_enrichment_jobs" in pcl_cases.metadata.tables:
        docket_enrichment_jobs = pcl_cases.metadata.tables["docket_enrichment_jobs"]
        clauses.append(
            exists(
                select(1).where(docket_enrichment_jobs.c.case_id == pcl_cases.c.id)
            )
        )
    if filters.sentencing_only and "sentencing_events" in pcl_cases.metadata.tables:
        sentencing_events = pcl_cases.metadata.tables["sentencing_events"]
        clauses.append(exists(has_sentencing_event_clause(pcl_cases, sentencing_events)))
    # Enrichment flags are not yet modeled; keep filters as no-ops.
    return clauses


def _maybe_table(engine, tables, name: str):
    table = tables.get(name)
    if table is None:
        return None
    try:
        inspector = inspect(engine)
        return table if inspector.has_table(table.name) else None
    except Exception:
        return None


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


def _load_case_fields(conn, tables, detail: Dict[str, Any]) -> List[Dict[str, Any]]:
    pcl_case_fields = tables.get("pcl_case_fields")
    case_id = detail.get("id")
    if pcl_case_fields is None or not case_id:
        return []
    stmt = (
        select(
            pcl_case_fields.c.field_name,
            pcl_case_fields.c.field_value_text,
            pcl_case_fields.c.field_value_json,
            pcl_case_fields.c.updated_at,
        )
        .where(pcl_case_fields.c.case_id == case_id)
        .order_by(pcl_case_fields.c.field_name.asc())
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


def _load_docket_jobs(conn, tables, detail: Dict[str, Any]) -> List[Dict[str, Any]]:
    job_table = tables["docket_enrichment_jobs"]
    receipt_table = tables["docket_enrichment_receipts"]
    case_id = detail.get("id")
    if not case_id:
        return []

    stmt = (
        select(
            job_table.c.id,
            job_table.c.case_id,
            job_table.c.include_docket_text,
            job_table.c.status,
            job_table.c.attempts,
            job_table.c.last_error,
            job_table.c.created_at,
            job_table.c.updated_at,
            job_table.c.started_at,
            job_table.c.finished_at,
            func.count(receipt_table.c.id).label("receipt_count"),
            func.max(receipt_table.c.created_at).label("last_receipt_at"),
        )
        .select_from(job_table.outerjoin(receipt_table, receipt_table.c.job_id == job_table.c.id))
        .where(job_table.c.case_id == case_id)
        .group_by(job_table.c.id)
        .order_by(desc(job_table.c.created_at), desc(job_table.c.id))
        .limit(25)
    )
    return [dict(row) for row in conn.execute(stmt).mappings().all()]


def _load_document_jobs(conn, tables, detail: Dict[str, Any]) -> List[Dict[str, Any]]:
    jobs_table = tables.get("docket_document_jobs")
    items_table = tables.get("docket_document_items")
    case_id = detail.get("id")
    if jobs_table is None or not case_id:
        return []
    job_rows = (
        conn.execute(
            select(jobs_table)
            .where(jobs_table.c.case_id == case_id)
            .order_by(desc(jobs_table.c.created_at), desc(jobs_table.c.id))
            .limit(25)
        )
        .mappings()
        .all()
    )
    jobs = [dict(row) for row in job_rows]
    if not items_table or not jobs:
        return jobs
    job_ids = [job["id"] for job in jobs]
    item_rows = (
        conn.execute(
            select(items_table)
            .where(items_table.c.job_id.in_(job_ids))
            .order_by(items_table.c.id.asc())
        )
        .mappings()
        .all()
    )
    items_by_job: Dict[int, List[Dict[str, Any]]] = {}
    for row in item_rows:
        item = dict(row)
        items_by_job.setdefault(item["job_id"], []).append(item)
    for job in jobs:
        job["items"] = items_by_job.get(job["id"], [])
    return jobs


def _estimate_docket_cost(conn, tables, detail: Dict[str, Any]) -> Dict[str, Any]:
    job_table = tables["docket_enrichment_jobs"]
    receipt_table = tables["docket_enrichment_receipts"]
    pcl_cases = tables["pcl_cases"]

    case_type = detail.get("case_type")
    case_id = detail.get("id")

    def _run(include_docket_text: bool, *, match_case_type: bool) -> Dict[str, Any]:
        join_stmt = job_table.join(receipt_table, receipt_table.c.job_id == job_table.c.id)
        where_clauses = [job_table.c.include_docket_text.is_(include_docket_text)]
        if case_id:
            where_clauses.append(job_table.c.case_id != case_id)
        if match_case_type and case_type:
            join_stmt = join_stmt.join(pcl_cases, pcl_cases.c.id == job_table.c.case_id)
            where_clauses.append(pcl_cases.c.case_type == case_type)

        stmt = (
            select(
                func.count(receipt_table.c.id).label("receipt_count"),
                func.avg(receipt_table.c.fee).label("avg_fee"),
                func.avg(receipt_table.c.billable_pages).label("avg_pages"),
            )
            .select_from(join_stmt)
            .where(and_(*where_clauses))
        )
        row = conn.execute(stmt).mappings().one()
        receipt_count = int(row["receipt_count"] or 0)
        return {
            "receipt_count": receipt_count,
            "avg_fee": float(row["avg_fee"]) if row["avg_fee"] is not None else None,
            "avg_billable_pages": float(row["avg_pages"]) if row["avg_pages"] is not None else None,
            "case_type_matched": bool(match_case_type and case_type),
        }

    case_type_estimates: Dict[bool, Dict[str, Any]] = {}
    fallback_estimates: Dict[bool, Dict[str, Any]] = {}
    for include_docket_text in (False, True):
        case_type_estimates[include_docket_text] = _run(
            include_docket_text, match_case_type=True
        )
        fallback_estimates[include_docket_text] = _run(
            include_docket_text, match_case_type=False
        )

    return {
        "case_type": case_type,
        "by_include_docket_text": {
            include: (
                case_type_estimates[include]
                if case_type_estimates[include]["receipt_count"] > 0
                else fallback_estimates[include]
            )
            for include in (False, True)
        },
    }


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


def _load_sentencing_detail(conn, tables, detail: Dict[str, Any]) -> Dict[str, Any]:
    if "sentencing_events" not in tables:
        return {"sentencing_events": [], "case_judges": [], "sentencing_judges": []}

    sentencing_events = tables["sentencing_events"]
    sentencing_evidence = tables["sentencing_evidence"]
    case_judges = tables["case_judges"]
    judges = tables["judges"]
    case_id = detail.get("id")
    if not case_id:
        return {"sentencing_events": [], "case_judges": [], "sentencing_judges": []}

    judge_stmt = (
        select(
            case_judges.c.id,
            case_judges.c.case_id,
            case_judges.c.judge_id,
            case_judges.c.role,
            case_judges.c.confidence,
            case_judges.c.source_system,
            case_judges.c.source_ref,
            judges.c.name_full.label("judge_name"),
            judges.c.court_id.label("judge_court_id"),
        )
        .select_from(case_judges.join(judges, judges.c.id == case_judges.c.judge_id))
        .where(case_judges.c.case_id == case_id)
        .order_by(case_judges.c.role.asc(), case_judges.c.confidence.desc())
    )

    event_stmt = (
        select(sentencing_events)
        .where(sentencing_events.c.case_id == case_id)
        .order_by(sentencing_events.c.sentencing_date.desc(), sentencing_events.c.id.desc())
    )

    evidence_stmt = (
        select(
            sentencing_evidence.c.id,
            sentencing_evidence.c.sentencing_event_id,
            sentencing_evidence.c.source_type,
            sentencing_evidence.c.source_id,
            sentencing_evidence.c.reference_text,
            sentencing_evidence.c.created_at,
        )
        .join(
            sentencing_events,
            sentencing_events.c.id == sentencing_evidence.c.sentencing_event_id,
        )
        .where(sentencing_events.c.case_id == case_id)
        .order_by(sentencing_evidence.c.id.asc())
    )

    judge_rows = [dict(row) for row in conn.execute(judge_stmt).mappings().all()]
    event_rows = [dict(row) for row in conn.execute(event_stmt).mappings().all()]
    evidence_rows = [dict(row) for row in conn.execute(evidence_stmt).mappings().all()]

    evidence_by_event: Dict[int, List[Dict[str, Any]]] = {}
    for evidence in evidence_rows:
        evidence_by_event.setdefault(int(evidence["sentencing_event_id"]), []).append(evidence)

    for event in event_rows:
        event_id = int(event["id"])
        event["evidence"] = evidence_by_event.get(event_id, [])

    sentencing_judges = [row for row in judge_rows if row.get("role") == "sentencing"]

    return {
        "sentencing_events": event_rows,
        "case_judges": judge_rows,
        "sentencing_judges": sentencing_judges,
    }
