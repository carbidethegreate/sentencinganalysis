from __future__ import annotations

import json
import math
import os
import re
import statistics
from dataclasses import asdict, dataclass
from datetime import date
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import requests
from sqlalchemy import and_, exists, func, or_, select


CRIMINAL_CASE_TYPE_CODES = {
    "cr",
    "crm",
    "crim",
    "criminal",
    "ncrim",
    "dcrim",
}

SENTENCING_SIGNAL_PATTERNS: Dict[str, re.Pattern[str]] = {
    "sentencing": re.compile(r"\bsentenc(?:ing|ed|e)\b", re.IGNORECASE),
    "judgment": re.compile(r"\bjudgment\b", re.IGNORECASE),
    "statement_of_reasons": re.compile(r"\bstatement of reasons\b|\bsor\b", re.IGNORECASE),
    "guideline": re.compile(r"\bguideline(?:s)?\b", re.IGNORECASE),
    "presentence": re.compile(r"\bpresentence\b|\bpsr\b|\bpsi\b", re.IGNORECASE),
}

REDUCTION_SIGNAL_PATTERNS: Dict[str, re.Pattern[str]] = {
    "5k1_1": re.compile(r"\b5k1\.?1\b|u\.?s\.?s\.?g\.?\s*§?\s*5k1\.?1", re.IGNORECASE),
    "rule_35": re.compile(r"\brule\s*35\b", re.IGNORECASE),
    "substantial_assistance": re.compile(r"\bsubstantial assistance\b", re.IGNORECASE),
    "downward_departure": re.compile(r"\bdownward departure\b", re.IGNORECASE),
    "variance": re.compile(r"\bvariance\b", re.IGNORECASE),
    "cooperation": re.compile(r"\bcooperat(?:ion|e|ed|ing)\b", re.IGNORECASE),
    "sentence_reduction": re.compile(
        r"\breduction of sentence\b|\bsentence reduction\b|\bmotion to reduce sentence\b",
        re.IGNORECASE,
    ),
}

MONTH_PATTERNS: Sequence[re.Pattern[str]] = (
    re.compile(
        r"(?:imprisonment|custody|incarceration|sentenced?\s+to)\D{0,60}?(\d{1,3})\s+months?\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(\d{1,3})\s+months?\b(?:\s+imprisonment|\s+custody|\s+incarceration)",
        re.IGNORECASE,
    ),
)


@dataclass
class DeepResearchFilters:
    question: str
    judge_name: Optional[str] = None
    person_name: Optional[str] = None
    court_id: Optional[str] = None
    date_from: Optional[date] = None
    date_to: Optional[date] = None
    criminal_only: bool = True
    include_docket_entries: bool = True
    include_document_text: bool = True
    include_sentencing_events: bool = True
    only_reduction_signals: bool = False
    min_text_confidence: float = 0.85
    max_cases: int = 250
    max_evidence_per_case: int = 8
    max_total_evidence: int = 400


def run_deep_research(
    engine: Any,
    tables: Dict[str, Any],
    filters: DeepResearchFilters,
    *,
    openai_api_key: Optional[str],
    model: Optional[str] = None,
    logger: Optional[Any] = None,
) -> Dict[str, Any]:
    cases = _load_cases(engine, tables, filters)
    case_ids = [int(row["id"]) for row in cases]
    case_map = {int(row["id"]): row for row in cases}

    evidence_rows: List[Dict[str, Any]] = []
    case_signal_map: Dict[int, Dict[str, Any]] = {
        case_id: {
            "sentencing_hits": 0,
            "reduction_hits": 0,
            "reduction_terms": set(),
            "sources": set(),
            "sentence_months": [],
        }
        for case_id in case_ids
    }

    docket_entry_count = 0
    document_count = 0

    if case_ids and filters.include_docket_entries:
        docket_rows, docket_entry_count = _collect_docket_entry_evidence(
            engine,
            tables,
            case_map,
            filters,
            case_signal_map,
        )
        evidence_rows.extend(docket_rows)

    if case_ids and filters.include_document_text:
        document_rows, document_count = _collect_document_evidence(
            engine,
            tables,
            case_map,
            filters,
            case_signal_map,
        )
        evidence_rows.extend(document_rows)

    sentencing_rows: List[Dict[str, Any]] = []
    if case_ids and filters.include_sentencing_events:
        sentencing_rows = _load_sentencing_events(engine, tables, case_ids)
        for row in sentencing_rows:
            case_id = int(row.get("case_id") or 0)
            months = _safe_int(row.get("sentence_months"))
            if case_id in case_signal_map and months is not None and 0 <= months <= 960:
                case_signal_map[case_id]["sentence_months"].append(months)
                case_signal_map[case_id]["sentencing_hits"] += 1

    candidate_rows = _build_candidate_rows(case_map, case_signal_map)
    evidence_rows = _trim_evidence(evidence_rows, filters.max_total_evidence)
    stats = _build_stats(
        case_rows=cases,
        evidence_rows=evidence_rows,
        sentencing_rows=sentencing_rows,
        case_signal_map=case_signal_map,
        docket_entry_count=docket_entry_count,
        document_count=document_count,
    )

    analysis_text, analysis_model, analysis_error = _generate_analysis_text(
        filters=filters,
        stats=stats,
        candidate_rows=candidate_rows,
        evidence_rows=evidence_rows,
        openai_api_key=openai_api_key,
        model=model,
    )

    if analysis_error and logger is not None:
        logger.warning("Deep research analysis fallback used: %s", analysis_error)

    return {
        "filters": asdict(filters),
        "stats": stats,
        "candidate_cases": candidate_rows,
        "evidence_rows": evidence_rows,
        "analysis_markdown": analysis_text,
        "analysis_model": analysis_model,
        "analysis_error": analysis_error,
    }


def _load_cases(engine: Any, tables: Dict[str, Any], filters: DeepResearchFilters) -> List[Dict[str, Any]]:
    pcl_cases = tables["pcl_cases"]
    case_judges = tables.get("case_judges")
    judges = tables.get("judges")
    pcl_parties = tables.get("pcl_parties")
    case_entities = tables.get("case_entities")

    select_columns = [pcl_cases.c.id]
    for name in (
        "case_number",
        "case_number_full",
        "case_name",
        "case_title",
        "case_type",
        "court_id",
        "date_filed",
        "date_closed",
        "judge_last_name",
    ):
        if name in pcl_cases.c:
            select_columns.append(pcl_cases.c[name])
    stmt = select(*select_columns)
    where_clauses = []

    case_type_col = pcl_cases.c["case_type"] if "case_type" in pcl_cases.c else None
    if filters.criminal_only and case_type_col is not None:
        where_clauses.append(
            func.lower(func.coalesce(case_type_col, "")).in_(sorted(CRIMINAL_CASE_TYPE_CODES))
        )
    court_col = pcl_cases.c["court_id"] if "court_id" in pcl_cases.c else None
    if filters.court_id and court_col is not None:
        where_clauses.append(
            func.lower(func.coalesce(court_col, "")) == filters.court_id.strip().lower()
        )
    date_filed_col = pcl_cases.c["date_filed"] if "date_filed" in pcl_cases.c else None
    if filters.date_from and date_filed_col is not None:
        where_clauses.append(date_filed_col >= filters.date_from)
    if filters.date_to and date_filed_col is not None:
        where_clauses.append(date_filed_col <= filters.date_to)

    judge_last_col = pcl_cases.c["judge_last_name"] if "judge_last_name" in pcl_cases.c else None
    judge_filter = (filters.judge_name or "").strip()
    if judge_filter:
        judge_pattern = f"%{judge_filter.lower()}%"
        judge_last = judge_filter.split()[-1].lower()
        judge_name_clause = (
            func.lower(func.coalesce(judge_last_col, "")).like(f"%{judge_last}%")
            if judge_last_col is not None
            else None
        )
        if case_judges is not None and judges is not None:
            judge_exists = exists(
                select(1)
                .select_from(case_judges.join(judges, case_judges.c.judge_id == judges.c.id))
                .where(
                    case_judges.c.case_id == pcl_cases.c.id,
                    or_(
                        func.lower(func.coalesce(judges.c.name_full, "")).like(judge_pattern),
                        func.lower(func.coalesce(judges.c.name_last, "")).like(
                            f"%{judge_last}%"
                        ),
                    ),
                )
            )
            if judge_name_clause is None:
                judge_name_clause = judge_exists
            else:
                judge_name_clause = or_(judge_name_clause, judge_exists)
        if judge_name_clause is not None:
            where_clauses.append(judge_name_clause)

    person_filter = (filters.person_name or "").strip()
    if person_filter:
        person_pattern = f"%{person_filter.lower()}%"
        person_clauses: List[Any] = []
        if pcl_parties is not None:
            person_clauses.append(
                exists(
                    select(1).where(
                        pcl_parties.c.case_id == pcl_cases.c.id,
                        or_(
                            func.lower(func.coalesce(pcl_parties.c.party_name, "")).like(
                                person_pattern
                            ),
                            func.lower(func.coalesce(pcl_parties.c.last_name, "")).like(
                                person_pattern
                            ),
                            func.lower(func.coalesce(pcl_parties.c.first_name, "")).like(
                                person_pattern
                            ),
                        ),
                    )
                )
            )
        if case_entities is not None:
            person_clauses.append(
                exists(
                    select(1).where(
                        case_entities.c.case_id == pcl_cases.c.id,
                        case_entities.c.entity_type.in_(["party", "attorney", "judge"]),
                        func.lower(func.coalesce(case_entities.c.value, "")).like(person_pattern),
                    )
                )
            )
        if person_clauses:
            where_clauses.append(or_(*person_clauses))

    if where_clauses:
        stmt = stmt.where(and_(*where_clauses))

    if date_filed_col is not None:
        stmt = stmt.order_by(date_filed_col.desc().nullslast(), pcl_cases.c.id.desc())
    else:
        stmt = stmt.order_by(pcl_cases.c.id.desc())
    stmt = stmt.limit(max(1, int(filters.max_cases)))

    with engine.begin() as conn:
        rows = conn.execute(stmt).mappings().all()
    return [dict(row) for row in rows]


def _collect_docket_entry_evidence(
    engine: Any,
    tables: Dict[str, Any],
    case_map: Dict[int, Dict[str, Any]],
    filters: DeepResearchFilters,
    case_signal_map: Dict[int, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], int]:
    pcl_case_fields = tables.get("pcl_case_fields")
    if pcl_case_fields is None or not case_map:
        return [], 0
    case_ids = sorted(case_map.keys())
    rows: List[Dict[str, Any]] = []
    total_entries = 0
    per_case_evidence: Dict[int, int] = {case_id: 0 for case_id in case_ids}

    for chunk in _chunks(case_ids, 500):
        stmt = (
            select(
                pcl_case_fields.c.case_id,
                pcl_case_fields.c.field_value_json,
            )
            .where(
                pcl_case_fields.c.case_id.in_(chunk),
                pcl_case_fields.c.field_name == "docket_entries",
            )
            .order_by(pcl_case_fields.c.case_id.asc())
        )
        with engine.begin() as conn:
            entries_rows = conn.execute(stmt).mappings().all()

        for entry_row in entries_rows:
            case_id = int(entry_row.get("case_id"))
            entry_list = _coerce_list(entry_row.get("field_value_json"))
            if not entry_list:
                continue
            for raw_entry in entry_list:
                if not isinstance(raw_entry, dict):
                    continue
                total_entries += 1
                description = _clean_text(
                    raw_entry.get("description")
                    or raw_entry.get("docketText")
                    or raw_entry.get("shortDescription")
                    or ""
                )
                if not description:
                    continue
                reductions = _matching_labels(description, REDUCTION_SIGNAL_PATTERNS)
                sentencing = _matching_labels(description, SENTENCING_SIGNAL_PATTERNS)
                if filters.only_reduction_signals and not reductions:
                    continue
                if not reductions and not sentencing:
                    continue

                signal = case_signal_map.get(case_id)
                if signal is None:
                    continue
                signal["sentencing_hits"] += int(bool(sentencing))
                signal["reduction_hits"] += int(bool(reductions))
                signal["sources"].add("docket_entry")
                for label in reductions:
                    signal["reduction_terms"].add(label)
                months = _extract_months(description)
                if months is not None:
                    signal["sentence_months"].append(months)

                if per_case_evidence.get(case_id, 0) >= filters.max_evidence_per_case:
                    continue
                per_case_evidence[case_id] = per_case_evidence.get(case_id, 0) + 1
                rows.append(
                    {
                        "case_id": case_id,
                        "case_number": _display_case_number(case_map.get(case_id) or {}),
                        "source_type": "docket_entry",
                        "source_id": str(raw_entry.get("documentNumber") or ""),
                        "source_date": str(raw_entry.get("dateFiled") or raw_entry.get("docketTextDate") or ""),
                        "signal_labels": sorted(set(reductions + sentencing)),
                        "snippet": description[:900],
                        "confidence": 1.0,
                    }
                )
    return rows, total_entries


def _collect_document_evidence(
    engine: Any,
    tables: Dict[str, Any],
    case_map: Dict[int, Dict[str, Any]],
    filters: DeepResearchFilters,
    case_signal_map: Dict[int, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], int]:
    jobs_table = tables.get("docket_document_jobs")
    items_table = tables.get("docket_document_items")
    if jobs_table is None or items_table is None or not case_map:
        return [], 0

    case_ids = sorted(case_map.keys())
    total_documents = 0
    rows: List[Dict[str, Any]] = []
    per_case_evidence: Dict[int, int] = {case_id: 0 for case_id in case_ids}

    for chunk in _chunks(case_ids, 300):
        stmt = (
            select(
                jobs_table.c.case_id,
                items_table.c.id,
                items_table.c.document_number,
                items_table.c.description,
                items_table.c.text_confidence,
                items_table.c.text_content,
                items_table.c.text_path,
            )
            .select_from(items_table.join(jobs_table, jobs_table.c.id == items_table.c.job_id))
            .where(
                jobs_table.c.case_id.in_(chunk),
                items_table.c.status == "downloaded",
                items_table.c.text_status == "completed",
                func.coalesce(items_table.c.text_confidence, 0.0) >= float(filters.min_text_confidence),
            )
            .order_by(jobs_table.c.case_id.asc(), items_table.c.id.asc())
        )
        with engine.begin() as conn:
            doc_rows = conn.execute(stmt).mappings().all()

        for doc in doc_rows:
            total_documents += 1
            case_id = int(doc.get("case_id"))
            text = _clean_text(doc.get("text_content") or "")
            if not text:
                text = _load_text_from_path(doc.get("text_path"))
            if not text:
                continue
            if len(text) > 12000:
                text = text[:12000]
            haystack = " ".join(
                [
                    _clean_text(doc.get("description") or ""),
                    text,
                ]
            )
            reductions = _matching_labels(haystack, REDUCTION_SIGNAL_PATTERNS)
            sentencing = _matching_labels(haystack, SENTENCING_SIGNAL_PATTERNS)
            if filters.only_reduction_signals and not reductions:
                continue
            if not reductions and not sentencing:
                continue

            signal = case_signal_map.get(case_id)
            if signal is None:
                continue
            signal["sentencing_hits"] += int(bool(sentencing))
            signal["reduction_hits"] += int(bool(reductions))
            signal["sources"].add("document")
            for label in reductions:
                signal["reduction_terms"].add(label)
            months = _extract_months(haystack)
            if months is not None:
                signal["sentence_months"].append(months)

            if per_case_evidence.get(case_id, 0) >= filters.max_evidence_per_case:
                continue
            per_case_evidence[case_id] = per_case_evidence.get(case_id, 0) + 1
            rows.append(
                {
                    "case_id": case_id,
                    "case_number": _display_case_number(case_map.get(case_id) or {}),
                    "source_type": "document",
                    "source_id": str(doc.get("document_number") or doc.get("id") or ""),
                    "source_date": "",
                    "signal_labels": sorted(set(reductions + sentencing)),
                    "snippet": _snippet_for_signals(haystack, reductions + sentencing),
                    "confidence": float(doc.get("text_confidence") or 0.0),
                }
            )
    return rows, total_documents


def _load_sentencing_events(engine: Any, tables: Dict[str, Any], case_ids: Sequence[int]) -> List[Dict[str, Any]]:
    sentencing_events = tables.get("sentencing_events")
    if sentencing_events is None or not case_ids:
        return []
    rows: List[Dict[str, Any]] = []
    for chunk in _chunks(case_ids, 500):
        stmt = (
            select(
                sentencing_events.c.id,
                sentencing_events.c.case_id,
                sentencing_events.c.sentencing_date,
                sentencing_events.c.sentence_months,
                sentencing_events.c.variance_type,
                sentencing_events.c.guideline_range_low,
                sentencing_events.c.guideline_range_high,
            )
            .where(sentencing_events.c.case_id.in_(chunk))
            .order_by(sentencing_events.c.sentencing_date.desc(), sentencing_events.c.id.desc())
        )
        with engine.begin() as conn:
            rows.extend([dict(row) for row in conn.execute(stmt).mappings().all()])
    return rows


def _build_candidate_rows(
    case_map: Dict[int, Dict[str, Any]],
    case_signal_map: Dict[int, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for case_id, signals in case_signal_map.items():
        reduction_terms = sorted(signals.get("reduction_terms") or [])
        if not reduction_terms and int(signals.get("reduction_hits") or 0) <= 0:
            continue
        months = [int(x) for x in signals.get("sentence_months") or [] if isinstance(x, int)]
        representative_months = int(round(statistics.median(months))) if months else None
        case_row = case_map.get(case_id) or {}
        score = int(signals.get("reduction_hits") or 0) * 3 + int(signals.get("sentencing_hits") or 0)
        rows.append(
            {
                "case_id": case_id,
                "case_number": _display_case_number(case_row),
                "case_title": case_row.get("case_title") or case_row.get("case_name") or "",
                "court_id": case_row.get("court_id") or "",
                "date_filed": _fmt_date(case_row.get("date_filed")),
                "date_closed": _fmt_date(case_row.get("date_closed")),
                "judge_last_name": case_row.get("judge_last_name") or "",
                "reduction_score": score,
                "reduction_terms": reduction_terms,
                "sentencing_signal_count": int(signals.get("sentencing_hits") or 0),
                "reduction_signal_count": int(signals.get("reduction_hits") or 0),
                "source_types": sorted(signals.get("sources") or []),
                "representative_sentence_months": representative_months,
            }
        )
    rows.sort(
        key=lambda row: (
            int(row.get("reduction_score") or 0),
            int(row.get("reduction_signal_count") or 0),
            int(row.get("sentencing_signal_count") or 0),
        ),
        reverse=True,
    )
    return rows


def _build_stats(
    *,
    case_rows: Sequence[Dict[str, Any]],
    evidence_rows: Sequence[Dict[str, Any]],
    sentencing_rows: Sequence[Dict[str, Any]],
    case_signal_map: Dict[int, Dict[str, Any]],
    docket_entry_count: int,
    document_count: int,
) -> Dict[str, Any]:
    case_count = len(case_rows)
    reduction_case_ids = sorted(
        [
            case_id
            for case_id, signal in case_signal_map.items()
            if int(signal.get("reduction_hits") or 0) > 0
        ]
    )
    sentencing_case_ids = sorted(
        [
            case_id
            for case_id, signal in case_signal_map.items()
            if int(signal.get("sentencing_hits") or 0) > 0
        ]
    )
    reduction_terms: Dict[str, int] = {}
    for signal in case_signal_map.values():
        for label in signal.get("reduction_terms") or []:
            reduction_terms[label] = reduction_terms.get(label, 0) + 1

    sentence_values = [
        int(row.get("sentence_months"))
        for row in sentencing_rows
        if _safe_int(row.get("sentence_months")) is not None
    ]
    sentence_stats = _numeric_stats(sentence_values)

    variance_counts: Dict[str, int] = {}
    for row in sentencing_rows:
        variance = (row.get("variance_type") or "").strip().lower() or "unknown"
        variance_counts[variance] = variance_counts.get(variance, 0) + 1

    evidence_by_source: Dict[str, int] = {}
    for row in evidence_rows:
        key = str(row.get("source_type") or "unknown")
        evidence_by_source[key] = evidence_by_source.get(key, 0) + 1

    return {
        "case_count": case_count,
        "docket_entries_scanned": docket_entry_count,
        "documents_scanned": document_count,
        "evidence_row_count": len(evidence_rows),
        "evidence_by_source": evidence_by_source,
        "cases_with_sentencing_signals": len(sentencing_case_ids),
        "cases_with_reduction_signals": len(reduction_case_ids),
        "reduction_terms_case_counts": dict(sorted(reduction_terms.items(), key=lambda item: item[1], reverse=True)),
        "sentencing_event_count": len(sentencing_rows),
        "sentence_months_stats": sentence_stats,
        "variance_type_counts": dict(sorted(variance_counts.items(), key=lambda item: item[1], reverse=True)),
    }


def _generate_analysis_text(
    *,
    filters: DeepResearchFilters,
    stats: Dict[str, Any],
    candidate_rows: Sequence[Dict[str, Any]],
    evidence_rows: Sequence[Dict[str, Any]],
    openai_api_key: Optional[str],
    model: Optional[str],
) -> Tuple[str, str, Optional[str]]:
    resolved_model = (model or os.environ.get("OPENAI_DEEP_RESEARCH_MODEL") or "gpt-5.2").strip()
    if not openai_api_key:
        return _fallback_analysis(filters, stats, candidate_rows), "fallback", "missing_openai_api_key"

    context_payload = {
        "filters": asdict(filters),
        "stats": stats,
        "candidate_cases": list(candidate_rows)[:120],
        "evidence_rows": list(evidence_rows)[:180],
    }
    system_prompt = (
        "You are a federal criminal sentencing analyst. "
        "Write a precise legal-style analysis grounded only in provided docket/document evidence. "
        "Always cite case numbers and source IDs when making claims. "
        "Include: key findings, reduction-signal analysis (5K1.1/Rule 35/cooperation/variance/departure), "
        "statistical summary, and limitations."
    )
    user_prompt = json.dumps(
        {
            "question": filters.question,
            "analysis_scope": {
                "judge_name": filters.judge_name,
                "person_name": filters.person_name,
                "court_id": filters.court_id,
                "date_from": _fmt_date(filters.date_from),
                "date_to": _fmt_date(filters.date_to),
            },
            "dataset": context_payload,
        },
        ensure_ascii=False,
    )
    req = {
        "model": resolved_model,
        "temperature": 0.1,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }
    try:
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {openai_api_key}",
                "Content-Type": "application/json",
            },
            json=req,
            timeout=240,
        )
        response.raise_for_status()
        payload = response.json()
        text = (
            payload.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
            .strip()
        )
        if not text:
            return _fallback_analysis(filters, stats, candidate_rows), resolved_model, "empty_openai_response"
        return text, resolved_model, None
    except Exception as exc:
        return _fallback_analysis(filters, stats, candidate_rows), resolved_model, str(exc)


def _fallback_analysis(
    filters: DeepResearchFilters,
    stats: Dict[str, Any],
    candidate_rows: Sequence[Dict[str, Any]],
) -> str:
    lines = [
        "## Sentencing Pattern Analysis",
        "",
        f"- Cases analyzed: {stats.get('case_count', 0)}",
        f"- Cases with sentencing signals: {stats.get('cases_with_sentencing_signals', 0)}",
        f"- Cases with reduction signals: {stats.get('cases_with_reduction_signals', 0)}",
        f"- Docket entries scanned: {stats.get('docket_entries_scanned', 0)}",
        f"- Documents scanned: {stats.get('documents_scanned', 0)}",
    ]
    sentence_stats = stats.get("sentence_months_stats") or {}
    if sentence_stats.get("count", 0):
        lines.extend(
            [
                "",
                "### Sentence Length Stats (months)",
                f"- Count: {sentence_stats.get('count')}",
                f"- Mean: {sentence_stats.get('mean')}",
                f"- Median: {sentence_stats.get('median')}",
                f"- Min/Max: {sentence_stats.get('min')} / {sentence_stats.get('max')}",
            ]
        )
    reduction_terms = stats.get("reduction_terms_case_counts") or {}
    if reduction_terms:
        lines.append("")
        lines.append("### Reduction Signals")
        for label, value in list(reduction_terms.items())[:10]:
            lines.append(f"- {label}: {value} case(s)")
    if candidate_rows:
        lines.append("")
        lines.append("### Top Candidate Cases for Sentence Reduction Patterns")
        for row in list(candidate_rows)[:12]:
            terms = ", ".join(row.get("reduction_terms") or [])
            lines.append(
                f"- {row.get('case_number')}: score={row.get('reduction_score')} terms={terms or 'n/a'}"
            )
    lines.extend(
        [
            "",
            "### Scope",
            f"- Judge filter: {filters.judge_name or 'none'}",
            f"- Person filter: {filters.person_name or 'none'}",
            f"- Court filter: {filters.court_id or 'none'}",
            f"- Date range: {_fmt_date(filters.date_from) or 'any'} to {_fmt_date(filters.date_to) or 'any'}",
            "",
            "### Notes",
            "- This fallback analysis is deterministic because OpenAI analysis was unavailable.",
            "- Use the candidate case list and evidence table for manual verification of key filings.",
        ]
    )
    return "\n".join(lines).strip()


def _trim_evidence(rows: Sequence[Dict[str, Any]], max_rows: int) -> List[Dict[str, Any]]:
    if len(rows) <= max_rows:
        return [dict(row) for row in rows]
    ordered = sorted(
        rows,
        key=lambda row: (
            1 if row.get("source_type") == "document" else 0,
            len(row.get("signal_labels") or []),
            float(row.get("confidence") or 0.0),
        ),
        reverse=True,
    )
    return [dict(row) for row in ordered[:max_rows]]


def _numeric_stats(values: Sequence[int]) -> Dict[str, Any]:
    clean = sorted([int(v) for v in values if isinstance(v, int) and not math.isnan(float(v))])
    if not clean:
        return {"count": 0}
    return {
        "count": len(clean),
        "min": clean[0],
        "max": clean[-1],
        "mean": round(sum(clean) / len(clean), 2),
        "median": float(statistics.median(clean)),
    }


def _extract_months(text: str) -> Optional[int]:
    raw = text or ""
    for pattern in MONTH_PATTERNS:
        match = pattern.search(raw)
        if not match:
            continue
        months = _safe_int(match.group(1))
        if months is None:
            continue
        if 0 <= months <= 960:
            return months
    return None


def _matching_labels(text: str, patterns: Dict[str, re.Pattern[str]]) -> List[str]:
    labels: List[str] = []
    haystack = text or ""
    for label, pattern in patterns.items():
        if pattern.search(haystack):
            labels.append(label)
    return labels


def _snippet_for_signals(text: str, labels: Iterable[str]) -> str:
    source = text or ""
    if not source:
        return ""
    for label in labels:
        if not label:
            continue
        marker = label.replace("_", " ")
        idx = source.lower().find(marker.lower())
        if idx >= 0:
            start = max(0, idx - 260)
            end = min(len(source), idx + 520)
            return source[start:end]
    return source[:900]


def _coerce_list(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return []
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            return []
        if isinstance(parsed, list):
            return parsed
    return []


def _clean_text(value: Any) -> str:
    if value is None:
        return ""
    return re.sub(r"\s+", " ", str(value)).strip()


def _load_text_from_path(path_value: Any) -> str:
    raw = _clean_text(path_value)
    if not raw or raw.startswith("s3://"):
        return ""
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = (Path.cwd() / path).resolve()
    if not path.exists() or not path.is_file():
        return ""
    try:
        return _clean_text(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return ""


def _chunks(values: Sequence[int], chunk_size: int) -> Iterable[List[int]]:
    current: List[int] = []
    for value in values:
        current.append(int(value))
        if len(current) >= chunk_size:
            yield current
            current = []
    if current:
        yield current


def _safe_int(value: Any) -> Optional[int]:
    try:
        if value is None:
            return None
        return int(value)
    except Exception:
        return None


def _fmt_date(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, date):
        return value.isoformat()
    return str(value)


def _display_case_number(case_row: Dict[str, Any]) -> str:
    return (
        case_row.get("case_number_full")
        or case_row.get("case_number")
        or case_row.get("id")
        or ""
    )
