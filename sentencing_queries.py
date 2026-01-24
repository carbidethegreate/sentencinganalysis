from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any, Dict, List, Optional, Sequence, Tuple

from sqlalchemy import Select, and_, func, select


@dataclass(frozen=True)
class SentencingReportFilters:
    judge_id: Optional[int] = None
    court_id: str = ""
    case_type: str = ""
    sentencing_date_from: Optional[date] = None
    sentencing_date_to: Optional[date] = None


def parse_sentencing_filters(args: Dict[str, str]) -> SentencingReportFilters:
    judge_id = _parse_optional_int(args.get("judge_id"))
    court_id = (args.get("court_id") or "").strip().lower()
    case_type = (args.get("case_type") or "").strip().lower()
    sentencing_date_from = _parse_date(args.get("sentencing_date_from"))
    sentencing_date_to = _parse_date(args.get("sentencing_date_to"))

    if sentencing_date_from and sentencing_date_to and sentencing_date_from > sentencing_date_to:
        sentencing_date_from, sentencing_date_to = sentencing_date_to, sentencing_date_from

    return SentencingReportFilters(
        judge_id=judge_id,
        court_id=court_id,
        case_type=case_type,
        sentencing_date_from=sentencing_date_from,
        sentencing_date_to=sentencing_date_to,
    )


def list_sentencing_events_by_judge(engine, tables, filters: SentencingReportFilters) -> Tuple[List[Dict[str, Any]], Sequence[str], Sequence[str]]:
    sentencing_events = tables["sentencing_events"]
    case_judges = tables["case_judges"]
    judges = tables["judges"]
    pcl_cases = tables["pcl_cases"]

    stmt = _build_report_stmt(sentencing_events, case_judges, judges, pcl_cases, filters)
    court_values_stmt = select(func.distinct(pcl_cases.c.court_id)).order_by(pcl_cases.c.court_id)
    case_type_values_stmt = select(func.distinct(pcl_cases.c.case_type)).order_by(pcl_cases.c.case_type)

    with engine.begin() as conn:
        rows = conn.execute(stmt).mappings().all()
        available_courts = [row[0] for row in conn.execute(court_values_stmt).all() if row[0]]
        available_case_types = [row[0] for row in conn.execute(case_type_values_stmt).all() if row[0]]

    return [dict(row) for row in rows], available_courts, available_case_types


def has_sentencing_event_clause(pcl_cases, sentencing_events) -> Select:
    return select(1).where(sentencing_events.c.case_id == pcl_cases.c.id).limit(1)


def _build_report_stmt(sentencing_events, case_judges, judges, pcl_cases, filters: SentencingReportFilters):
    join_stmt = (
        sentencing_events.join(pcl_cases, pcl_cases.c.id == sentencing_events.c.case_id)
        .join(case_judges, case_judges.c.case_id == pcl_cases.c.id)
        .join(judges, judges.c.id == case_judges.c.judge_id)
    )

    where_clauses = [case_judges.c.role == "sentencing"]
    if filters.judge_id:
        where_clauses.append(judges.c.id == filters.judge_id)
    if filters.court_id:
        where_clauses.append(pcl_cases.c.court_id == filters.court_id)
    if filters.case_type:
        where_clauses.append(pcl_cases.c.case_type == filters.case_type)
    if filters.sentencing_date_from:
        where_clauses.append(sentencing_events.c.sentencing_date >= filters.sentencing_date_from)
    if filters.sentencing_date_to:
        where_clauses.append(sentencing_events.c.sentencing_date <= filters.sentencing_date_to)

    return (
        select(
            sentencing_events.c.id,
            sentencing_events.c.case_id,
            sentencing_events.c.defendant_identifier,
            sentencing_events.c.sentencing_date,
            sentencing_events.c.guideline_range_low,
            sentencing_events.c.guideline_range_high,
            sentencing_events.c.offense_level,
            sentencing_events.c.criminal_history_category,
            sentencing_events.c.sentence_months,
            sentencing_events.c.variance_type,
            sentencing_events.c.notes,
            judges.c.id.label("judge_id"),
            judges.c.name_full.label("judge_name"),
            judges.c.court_id.label("judge_court_id"),
            case_judges.c.confidence.label("judge_confidence"),
            pcl_cases.c.court_id,
            pcl_cases.c.case_number,
            pcl_cases.c.case_number_full,
            pcl_cases.c.case_type,
            pcl_cases.c.short_title,
        )
        .select_from(join_stmt)
        .where(and_(*where_clauses))
        .order_by(sentencing_events.c.sentencing_date.desc(), sentencing_events.c.id.desc())
    )


def _parse_optional_int(value: Optional[str]) -> Optional[int]:
    if not value:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_date(value: Optional[str]) -> Optional[date]:
    if not value:
        return None
    try:
        return date.fromisoformat(value.strip())
    except ValueError:
        return None
