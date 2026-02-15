from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple

from sqlalchemy import Text, and_, cast, desc, exists, func, inspect, literal, or_, select

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


@dataclass(frozen=True)
class PclAttorneyListResult:
    rows: List[Dict[str, Any]]
    pagination: Pagination
    available_courts: Sequence[str]
    available_case_types: Sequence[str]


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
    case_entities = _maybe_table(engine, tables, "case_entities")

    where_clauses = _build_where_clauses(
        pcl_cases, filters, case_fields=case_fields, case_entities=case_entities
    )
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
    case_entities = _maybe_table(engine, tables, "case_entities")
    where_clauses = _build_where_clauses(
        pcl_cases, filters, case_fields=case_fields, case_entities=case_entities
    )
    enrichment_status = literal(None).label("enrichment_status")
    enrichment_updated_at = literal(None).label("enrichment_updated_at")
    enrichment_last_error = literal(None).label("enrichment_last_error")
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
        enrichment_last_error = (
            select(docket_enrichment_jobs.c.last_error)
            .where(docket_enrichment_jobs.c.case_id == pcl_cases.c.id)
            .order_by(
                docket_enrichment_jobs.c.created_at.desc(),
                docket_enrichment_jobs.c.id.desc(),
            )
            .limit(1)
            .scalar_subquery()
            .label("enrichment_last_error")
        )

    docket_judges = literal(None).label("docket_judges")
    docket_party_count = literal(None).label("docket_party_count")
    docket_party_names = literal(None).label("docket_party_names")
    docket_attorney_count = literal(None).label("docket_attorney_count")
    docket_entry_count = literal(None).label("docket_entry_count")
    docket_recent_entries = literal(None).label("docket_recent_entries")
    docket_attorney_names = literal(None).label("docket_attorney_names")
    docket_charges = literal(None).label("docket_charges")
    if case_fields is not None:
        docket_judges = (
            select(case_fields.c.field_value_json)
            .where(case_fields.c.case_id == pcl_cases.c.id)
            .where(case_fields.c.field_name == "docket_judges")
            .limit(1)
            .scalar_subquery()
            .label("docket_judges")
        )
        docket_party_count = (
            select(case_fields.c.field_value_json)
            .where(case_fields.c.case_id == pcl_cases.c.id)
            .where(case_fields.c.field_name == "docket_party_count")
            .limit(1)
            .scalar_subquery()
            .label("docket_party_count")
        )
        docket_party_names = (
            select(case_fields.c.field_value_json)
            .where(case_fields.c.case_id == pcl_cases.c.id)
            .where(case_fields.c.field_name == "docket_party_names")
            .limit(1)
            .scalar_subquery()
            .label("docket_party_names")
        )
        docket_attorney_count = (
            select(case_fields.c.field_value_json)
            .where(case_fields.c.case_id == pcl_cases.c.id)
            .where(case_fields.c.field_name == "docket_attorney_count")
            .limit(1)
            .scalar_subquery()
            .label("docket_attorney_count")
        )
        docket_entry_count = (
            select(case_fields.c.field_value_json)
            .where(case_fields.c.case_id == pcl_cases.c.id)
            .where(case_fields.c.field_name == "docket_entry_count")
            .limit(1)
            .scalar_subquery()
            .label("docket_entry_count")
        )
        docket_recent_entries = (
            select(case_fields.c.field_value_json)
            .where(case_fields.c.case_id == pcl_cases.c.id)
            .where(case_fields.c.field_name == "docket_recent_entries")
            .limit(1)
            .scalar_subquery()
            .label("docket_recent_entries")
        )
        docket_attorney_names = (
            select(case_fields.c.field_value_json)
            .where(case_fields.c.case_id == pcl_cases.c.id)
            .where(case_fields.c.field_name == "docket_attorney_names")
            .limit(1)
            .scalar_subquery()
            .label("docket_attorney_names")
        )
        docket_charges = (
            select(case_fields.c.field_value_json)
            .where(case_fields.c.case_id == pcl_cases.c.id)
            .where(case_fields.c.field_name == "docket_charges")
            .limit(1)
            .scalar_subquery()
            .label("docket_charges")
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
            pcl_cases.c.date_closed,
            pcl_cases.c.effective_date_closed,
            pcl_cases.c.judge_last_name,
            pcl_cases.c.case_year,
            pcl_cases.c.case_office,
            pcl_cases.c.case_link,
            pcl_cases.c.last_search_run_id,
            pcl_cases.c.last_search_run_at,
            enrichment_status,
            enrichment_updated_at,
            enrichment_last_error,
            docket_judges,
            docket_party_count,
            docket_party_names,
            docket_attorney_count,
            docket_entry_count,
            docket_recent_entries,
            docket_attorney_names,
            docket_charges,
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


def list_attorneys(
    engine,
    tables,
    *,
    search_text: str = "",
    court_id: str = "",
    case_type: str = "",
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> PclAttorneyListResult:
    pcl_cases = tables["pcl_cases"]
    pcl_case_fields = _maybe_table(engine, tables, "pcl_case_fields")
    if pcl_case_fields is None:
        return PclAttorneyListResult(
            rows=[],
            pagination=Pagination(page=1, page_size=page_size, total=0),
            available_courts=[],
            available_case_types=[],
        )

    normalized_search = (search_text or "").strip()
    normalized_court = (court_id or "").strip().lower()
    normalized_case_type = (case_type or "").strip().lower()
    page = max(1, int(page or 1))
    page_size = max(1, min(int(page_size or DEFAULT_PAGE_SIZE), MAX_PAGE_SIZE))

    where_clauses = [pcl_case_fields.c.field_name == "docket_attorneys"]
    if normalized_court:
        where_clauses.append(func.lower(pcl_cases.c.court_id) == normalized_court)
    if normalized_case_type:
        where_clauses.append(func.lower(func.coalesce(pcl_cases.c.case_type, "")) == normalized_case_type)
    if normalized_search:
        like_pattern = f"%{normalized_search.lower()}%"
        where_clauses.append(
            or_(
                func.lower(func.coalesce(cast(pcl_case_fields.c.field_value_json, Text), "")).like(
                    like_pattern
                ),
                func.lower(func.coalesce(pcl_cases.c.case_number, "")).like(like_pattern),
                func.lower(func.coalesce(pcl_cases.c.case_number_full, "")).like(like_pattern),
                func.lower(func.coalesce(pcl_cases.c.short_title, "")).like(like_pattern),
                func.lower(func.coalesce(pcl_cases.c.case_title, "")).like(like_pattern),
            )
        )

    stmt = (
        select(
            pcl_cases.c.id.label("case_id"),
            pcl_cases.c.court_id,
            pcl_cases.c.case_type,
            pcl_cases.c.case_number,
            pcl_cases.c.case_number_full,
            pcl_cases.c.short_title,
            pcl_cases.c.case_title,
            pcl_cases.c.date_filed,
            pcl_case_fields.c.field_value_json,
            pcl_case_fields.c.updated_at,
        )
        .select_from(pcl_case_fields.join(pcl_cases, pcl_case_fields.c.case_id == pcl_cases.c.id))
        .where(and_(*where_clauses))
        .order_by(pcl_case_fields.c.updated_at.desc(), pcl_cases.c.id.desc())
    )

    with engine.begin() as conn:
        source_rows = [dict(row) for row in conn.execute(stmt).mappings().all()]

    available_courts = sorted(
        {str(row.get("court_id")) for row in source_rows if row.get("court_id")}
    )
    available_case_types = sorted(
        {str(row.get("case_type")) for row in source_rows if row.get("case_type")}
    )
    attorneys = _aggregate_attorneys(source_rows, search_text=normalized_search)
    total = len(attorneys)
    offset = (page - 1) * page_size
    paged_rows = attorneys[offset : offset + page_size]

    return PclAttorneyListResult(
        rows=paged_rows,
        pagination=Pagination(page=page, page_size=page_size, total=total),
        available_courts=available_courts,
        available_case_types=available_case_types,
    )


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
    pcl_cases, filters: PclCaseFilters, *, case_fields=None, case_entities=None
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
        raw_needle = filters.search_text.lower()
        like_pattern = f"%{raw_needle}%"
        normalized_needle = re.sub(r"[^a-z0-9]+", " ", raw_needle)
        normalized_needle = re.sub(r"\s+", " ", normalized_needle).strip()
        normalized_like_pattern = (
            f"%{normalized_needle}%" if normalized_needle else like_pattern
        )
        search_clauses: List[Any] = [
            func.lower(func.coalesce(pcl_cases.c.case_number, "")).like(like_pattern),
            func.lower(func.coalesce(pcl_cases.c.case_number_full, "")).like(like_pattern),
            func.lower(func.coalesce(pcl_cases.c.short_title, "")).like(like_pattern),
            func.lower(func.coalesce(pcl_cases.c.case_title, "")).like(like_pattern),
        ]
        if case_entities is not None:
            search_clauses.append(
                exists(
                    select(1).where(
                        and_(
                            case_entities.c.case_id == pcl_cases.c.id,
                            func.lower(func.coalesce(case_entities.c.value_normalized, "")).like(
                                normalized_like_pattern
                            ),
                        )
                    )
                )
            )
        if case_fields is not None:
            # Allow the primary search box to match parties/counsel when docket metadata exists.
            #
            # NOTE: `docket_party_summary` is stored in `field_value_text` and is intentionally
            # truncated to keep the (field_name, field_value_text) btree index healthy. That
            # truncation can cause searches to miss counsel who appear later in long party/count
            # summaries. To keep search reliable for attorneys, we also search the compact JSON
            # name lists (`docket_attorney_names`, `docket_party_names`, etc.) which are not
            # truncated.
            search_clauses.append(
                exists(
                    select(1).where(
                        and_(
                            case_fields.c.case_id == pcl_cases.c.id,
                            case_fields.c.field_name == "docket_party_summary",
                            func.lower(func.coalesce(case_fields.c.field_value_text, "")).like(
                                like_pattern
                            ),
                        )
                    )
                )
            )
            for field_name in (
                "docket_attorney_names",
                "docket_party_names",
                "docket_judges",
                "docket_charges",
                "docket_attorneys",
                "docket_parties",
            ):
                search_clauses.append(
                    exists(
                        select(1).where(
                            and_(
                                case_fields.c.case_id == pcl_cases.c.id,
                                case_fields.c.field_name == field_name,
                                func.lower(
                                    func.coalesce(
                                        cast(case_fields.c.field_value_json, Text), ""
                                    )
                                ).like(like_pattern),
                            )
                        )
                    )
                )
        clauses.append(or_(*search_clauses))
    if (filters.field_name or filters.field_value) and case_fields is not None:
        field_clauses = [case_fields.c.case_id == pcl_cases.c.id]
        if filters.field_name:
            field_clauses.append(
                func.lower(case_fields.c.field_name) == filters.field_name.lower()
            )
        if filters.field_value:
            field_like = f"%{filters.field_value.lower()}%"
            field_clauses.append(
                or_(
                    func.lower(func.coalesce(case_fields.c.field_value_text, "")).like(
                        field_like
                    ),
                    func.lower(
                        func.coalesce(cast(case_fields.c.field_value_json, Text), "")
                    ).like(field_like),
                )
            )
        clauses.append(exists(select(1).where(and_(*field_clauses))))
    if filters.indexed_only:
        clauses.append(pcl_cases.c.record_hash.is_not(None))
    if filters.enriched_only:
        if case_fields is not None:
            clauses.append(
                exists(
                    select(1).where(
                        and_(
                            case_fields.c.case_id == pcl_cases.c.id,
                            case_fields.c.field_name.in_(
                                ["docket_entries", "docket_text", "docket_html"]
                            ),
                        )
                    )
                )
            )
        elif "docket_enrichment_jobs" in pcl_cases.metadata.tables:
            docket_enrichment_jobs = pcl_cases.metadata.tables["docket_enrichment_jobs"]
            clauses.append(
                exists(
                    select(1).where(docket_enrichment_jobs.c.case_id == pcl_cases.c.id)
                )
            )
    if filters.sentencing_only and "sentencing_events" in pcl_cases.metadata.tables:
        sentencing_events = pcl_cases.metadata.tables["sentencing_events"]
        clauses.append(exists(has_sentencing_event_clause(pcl_cases, sentencing_events)))
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
    if items_table is None or not jobs:
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


def estimate_docket_cost_for_filters(
    engine,
    tables,
    filters: PclCaseFilters,
    *,
    include_docket_text: bool,
) -> Dict[str, Any]:
    """Estimate docket-run cost for cases matching provided filters.

    The estimator prefers receipts from jobs within the same filter set, then
    falls back to the same case type and finally all historical docket jobs.
    """
    pcl_cases = tables["pcl_cases"]
    docket_jobs = tables["docket_enrichment_jobs"]
    docket_receipts = tables["docket_enrichment_receipts"]

    case_entities = _maybe_table(engine, tables, "case_entities")
    where_clauses = _build_where_clauses(
        pcl_cases, filters, case_fields=None, case_entities=case_entities
    )
    case_type = filters.case_type

    candidate_ids_stmt = select(pcl_cases.c.id).where(and_(*where_clauses))

    def _count_cases() -> int:
        stmt = select(func.count()).select_from(pcl_cases).where(and_(*where_clauses))
        with engine.begin() as conn:
            return int(conn.execute(stmt).scalar_one())

    def _run_estimate(where: Sequence[Any]) -> Dict[str, Any]:
        join_stmt = docket_jobs.join(
            docket_receipts, docket_receipts.c.job_id == docket_jobs.c.id
        ).join(pcl_cases, pcl_cases.c.id == docket_jobs.c.case_id)
        stmt = (
            select(
                func.count(docket_receipts.c.id).label("receipt_count"),
                func.avg(docket_receipts.c.fee).label("avg_fee"),
                func.avg(docket_receipts.c.billable_pages).label("avg_pages"),
            )
            .select_from(join_stmt)
            .where(and_(docket_jobs.c.include_docket_text.is_(include_docket_text), *where))
        )
        with engine.begin() as conn:
            row = conn.execute(stmt).mappings().one()
        receipt_count = int(row["receipt_count"] or 0)
        return {
            "receipt_count": receipt_count,
            "avg_fee": float(row["avg_fee"]) if row["avg_fee"] is not None else None,
            "avg_billable_pages": (
                float(row["avg_pages"]) if row["avg_pages"] is not None else None
            ),
        }

    scoped_match = _run_estimate([pcl_cases.c.id.in_(candidate_ids_stmt)])

    if scoped_match["receipt_count"] <= 0 and case_type:
        scoped_match = _run_estimate([pcl_cases.c.case_type == case_type])
        scoped_match["fallback"] = "case_type"
    elif scoped_match["receipt_count"] <= 0:
        scoped_match["fallback"] = "global"

    scoped_match.setdefault("fallback", "filter")
    candidate_count = _count_cases()
    avg_fee = scoped_match["avg_fee"]
    scoped_match["candidate_count"] = candidate_count
    scoped_match["estimated_total_fee"] = (
        avg_fee * candidate_count if avg_fee is not None else None
    )
    scoped_match["include_docket_text"] = include_docket_text
    return scoped_match


def _load_distinct(conn, column) -> List[str]:
    stmt = select(column).where(column.is_not(None)).group_by(column).order_by(column.asc())
    return [row[0] for row in conn.execute(stmt).all() if row[0]]


def _aggregate_attorneys(
    source_rows: List[Dict[str, Any]], *, search_text: str
) -> List[Dict[str, Any]]:
    attorneys: Dict[str, Dict[str, Any]] = {}
    needle = (search_text or "").strip().lower()
    for row in source_rows:
        payload = _coerce_json_value(row.get("field_value_json"))
        attorney_rows = _normalize_attorney_rows(payload)
        if not attorney_rows:
            continue
        case_ref = {
            "case_id": row.get("case_id"),
            "court_id": row.get("court_id"),
            "case_type": row.get("case_type"),
            "case_number": row.get("case_number"),
            "case_number_full": row.get("case_number_full"),
            "short_title": row.get("short_title"),
            "case_title": row.get("case_title"),
            "date_filed": row.get("date_filed"),
            "updated_at": row.get("updated_at"),
        }
        for attorney in attorney_rows:
            if needle and needle not in _build_attorney_search_blob(attorney, case_ref):
                continue
            key = _attorney_identity_key(attorney)
            bucket = attorneys.get(key)
            if bucket is None:
                bucket = _new_attorney_bucket(attorney, case_ref)
                attorneys[key] = bucket
            else:
                _merge_attorney_bucket(bucket, attorney, case_ref)

    # Consolidate duplicates that come from inconsistent identity keys
    # (ex: same name appears in the same case once with contact info and once without).
    _consolidate_attorney_buckets(attorneys)

    rows: List[Dict[str, Any]] = []
    for bucket in attorneys.values():
        rows.append(_finalize_attorney_bucket(bucket))
    rows.sort(
        key=lambda item: (
            -int(item.get("case_count") or 0),
            str(item.get("name") or "").lower(),
        )
    )
    return rows


def _coerce_json_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (list, dict)):
        return value
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None
    return None


def _normalize_attorney_rows(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, dict):
        maybe_rows = payload.get("attorneys")
        if isinstance(maybe_rows, list):
            payload = maybe_rows
        else:
            payload = []
    if not isinstance(payload, list):
        return []
    rows: List[Dict[str, Any]] = []
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        name = _clean_str(entry.get("name"))
        if not name:
            continue
        rows.append(
            {
                "name": name,
                "party_name": _clean_str(entry.get("party_name")),
                "party_type": _clean_str(entry.get("party_type")),
                "organization": _clean_str(entry.get("organization")),
                "emails": _normalize_string_list(entry.get("emails")),
                "phones": _normalize_string_list(entry.get("phones")),
                "faxes": _normalize_string_list(entry.get("faxes")),
                "websites": _normalize_string_list(entry.get("websites")),
                "designations": _normalize_string_list(entry.get("designations")),
                "roles": _normalize_string_list(entry.get("roles")),
                "details": _normalize_string_list(entry.get("details")),
                "raw_lines": _normalize_string_list(entry.get("raw_lines")),
            }
        )
    return rows


def _build_attorney_search_blob(attorney: Dict[str, Any], case_ref: Dict[str, Any]) -> str:
    parts: List[str] = []
    for key in (
        "name",
        "party_name",
        "party_type",
        "organization",
        "case_number",
        "case_number_full",
        "short_title",
        "case_title",
        "court_id",
        "case_type",
    ):
        value = attorney.get(key) if key in attorney else case_ref.get(key)
        if value:
            parts.append(str(value))
    for key in (
        "emails",
        "phones",
        "faxes",
        "websites",
        "designations",
        "roles",
        "details",
        "raw_lines",
    ):
        for item in attorney.get(key) or []:
            parts.append(str(item))
    return " | ".join(parts).lower()


def _attorney_identity_key(attorney: Dict[str, Any]) -> str:
    name = str(attorney.get("name") or "").strip().lower()
    email_key = ",".join(sorted(str(item).strip().lower() for item in attorney.get("emails") or []))
    phone_key = ",".join(
        sorted(
            "".join(ch for ch in str(item) if ch.isdigit())
            for item in attorney.get("phones") or []
        )
    )
    if email_key:
        return f"{name}|{email_key}"
    if phone_key:
        return f"{name}|{phone_key}"
    return name


def _bucket_case_id_set(bucket: Dict[str, Any]) -> set[int]:
    case_ids: set[int] = set()
    for row in bucket.get("case_rows") or []:
        case_id = row.get("case_id")
        if isinstance(case_id, int):
            case_ids.add(case_id)
    return case_ids


def _merge_attorney_buckets(dst: Dict[str, Any], src: Dict[str, Any]) -> None:
    for set_name in (
        "organization_set",
        "email_set",
        "phone_set",
        "fax_set",
        "website_set",
        "designation_set",
        "role_set",
        "detail_set",
        "raw_line_set",
    ):
        dst.setdefault(set_name, set()).update(src.get(set_name) or set())

    dst_keys = dst.setdefault("case_keys", set())
    dst_rows = dst.setdefault("case_rows", [])
    for row in src.get("case_rows") or []:
        if not isinstance(row, dict):
            continue
        case_key = (
            row.get("case_id"),
            row.get("party_name") or "",
            row.get("party_type") or "",
        )
        if case_key in dst_keys:
            continue
        dst_keys.add(case_key)
        dst_rows.append(row)

    src_seen = src.get("last_seen_at")
    dst_seen = dst.get("last_seen_at")
    if src_seen and (dst_seen is None or src_seen > dst_seen):
        dst["last_seen_at"] = src_seen


def _consolidate_attorney_buckets(attorneys: Dict[str, Dict[str, Any]]) -> None:
    by_name: Dict[str, List[str]] = {}
    for key, bucket in list(attorneys.items()):
        name_key = str(bucket.get("name") or "").strip().lower()
        if not name_key:
            continue
        by_name.setdefault(name_key, []).append(key)

    for _, keys in by_name.items():
        if len(keys) < 2:
            continue
        # Pairwise merge buckets that share at least one case id.
        # This fixes common duplicates caused by parsing variations.
        i = 0
        while i < len(keys):
            primary_key = keys[i]
            primary = attorneys.get(primary_key)
            if primary is None:
                i += 1
                continue
            primary_cases = _bucket_case_id_set(primary)
            j = i + 1
            while j < len(keys):
                other_key = keys[j]
                other = attorneys.get(other_key)
                if other is None:
                    keys.pop(j)
                    continue
                other_cases = _bucket_case_id_set(other)
                if primary_cases and other_cases and (primary_cases & other_cases):
                    _merge_attorney_buckets(primary, other)
                    primary_cases |= other_cases
                    del attorneys[other_key]
                    keys.pop(j)
                    continue
                j += 1
            i += 1


def _new_attorney_bucket(attorney: Dict[str, Any], case_ref: Dict[str, Any]) -> Dict[str, Any]:
    bucket = {
        "name": attorney.get("name"),
        "organization_set": set(attorney.get("organization") and [attorney["organization"]] or []),
        "email_set": set(attorney.get("emails") or []),
        "phone_set": set(attorney.get("phones") or []),
        "fax_set": set(attorney.get("faxes") or []),
        "website_set": set(attorney.get("websites") or []),
        "designation_set": set(attorney.get("designations") or []),
        "role_set": set(attorney.get("roles") or []),
        "detail_set": set(attorney.get("details") or []),
        "raw_line_set": set(attorney.get("raw_lines") or []),
        "case_rows": [],
        "case_keys": set(),
        "last_seen_at": case_ref.get("updated_at"),
    }
    _merge_attorney_bucket(bucket, attorney, case_ref)
    return bucket


def _merge_attorney_bucket(
    bucket: Dict[str, Any], attorney: Dict[str, Any], case_ref: Dict[str, Any]
) -> None:
    if attorney.get("organization"):
        bucket["organization_set"].add(attorney["organization"])
    for key, set_name in (
        ("emails", "email_set"),
        ("phones", "phone_set"),
        ("faxes", "fax_set"),
        ("websites", "website_set"),
        ("designations", "designation_set"),
        ("roles", "role_set"),
        ("details", "detail_set"),
        ("raw_lines", "raw_line_set"),
    ):
        for item in attorney.get(key) or []:
            bucket[set_name].add(item)
    case_id = case_ref.get("case_id")
    case_key = (
        case_id,
        attorney.get("party_name") or "",
        attorney.get("party_type") or "",
    )
    if case_key not in bucket["case_keys"]:
        bucket["case_keys"].add(case_key)
        bucket["case_rows"].append(
            {
                "case_id": case_id,
                "court_id": case_ref.get("court_id"),
                "case_type": case_ref.get("case_type"),
                "case_number": case_ref.get("case_number"),
                "case_number_full": case_ref.get("case_number_full"),
                "short_title": case_ref.get("short_title"),
                "case_title": case_ref.get("case_title"),
                "date_filed": case_ref.get("date_filed"),
                "party_name": attorney.get("party_name"),
                "party_type": attorney.get("party_type"),
            }
        )
    seen_at = case_ref.get("updated_at")
    if seen_at and (bucket.get("last_seen_at") is None or seen_at > bucket["last_seen_at"]):
        bucket["last_seen_at"] = seen_at


def _finalize_attorney_bucket(bucket: Dict[str, Any]) -> Dict[str, Any]:
    case_rows = list(bucket.get("case_rows") or [])
    case_rows.sort(
        key=lambda row: (
            str(row.get("date_filed") or ""),
            str(row.get("case_number_full") or row.get("case_number") or ""),
        ),
        reverse=True,
    )
    return {
        "name": bucket.get("name"),
        "organizations": sorted(bucket.get("organization_set") or []),
        "emails": sorted(bucket.get("email_set") or []),
        "phones": sorted(bucket.get("phone_set") or []),
        "faxes": sorted(bucket.get("fax_set") or []),
        "websites": sorted(bucket.get("website_set") or []),
        "designations": sorted(bucket.get("designation_set") or []),
        "roles": sorted(bucket.get("role_set") or []),
        "details": sorted(bucket.get("detail_set") or []),
        "raw_lines": sorted(bucket.get("raw_line_set") or []),
        "case_count": len(case_rows),
        "related_cases": case_rows,
        "last_seen_at": bucket.get("last_seen_at"),
    }


def _normalize_string_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        cleaned = _clean_str(value)
        return [cleaned] if cleaned else []
    if not isinstance(value, list):
        return []
    output: List[str] = []
    for item in value:
        cleaned = _clean_str(item)
        if cleaned and cleaned not in output:
            output.append(cleaned)
    return output


def _clean_str(value: Any) -> str:
    if value is None:
        return ""
    cleaned = " ".join(str(value).split()).strip()
    return cleaned


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
