from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import html
import json
import os
import re
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlencode, urljoin, urlparse
from xml.etree import ElementTree

from lxml import html as lxml_html
from lxml import etree as lxml_etree
from sqlalchemy import Table, inspect, select, update, or_


TERMINAL_FAILURE_MESSAGE = "endpoint not yet implemented"


@dataclass(frozen=True)
class DocketJob:
    id: int
    case_id: int
    include_docket_text: bool
    status: str
    attempts: int


@dataclass(frozen=True)
class DocketFetchResult:
    url: str
    status_code: int
    content_type: str
    body: bytes
    headers: Dict[str, Any] = field(default_factory=dict)
    form_action: Optional[str] = None
    form_payload: Optional[Dict[str, str]] = None
    request_debug: Optional[Dict[str, Any]] = None


class DocketEnrichmentWorker:
    def __init__(
        self,
        engine,
        tables: Dict[str, Table],
        *,
        logger: Optional[Any] = None,
        now_fn: Callable[[], datetime] = None,
        endpoint_available: bool = False,
        http_client: Optional[Any] = None,
        docket_output: str = "html",
        docket_url_template: Optional[str] = None,
    ) -> None:
        self._engine = engine
        self._tables = tables
        self._logger = logger
        self._now = now_fn or datetime.utcnow
        self._endpoint_available = endpoint_available
        self._http_client = http_client
        self._docket_output = docket_output
        self._docket_url_template = docket_url_template

    def run_once(self, max_jobs: int = 5) -> int:
        jobs = self._load_jobs(max_jobs)
        processed = 0
        for job in jobs:
            self._process_job(job)
            processed += 1
        return processed

    def run_jobs(self, job_ids: List[int]) -> int:
        if not job_ids:
            return 0
        jobs = self._load_jobs_by_ids(job_ids)
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

    def _load_jobs_by_ids(self, job_ids: List[int]) -> List[Dict[str, Any]]:
        job_table = self._tables["docket_enrichment_jobs"]
        with self._engine.begin() as conn:
            rows = (
                conn.execute(
                    select(job_table)
                    .where(job_table.c.id.in_(job_ids))
                    .where(job_table.c.status.in_(["queued", "running"]))
                    .order_by(job_table.c.created_at.asc(), job_table.c.id.asc())
                )
                .mappings()
                .all()
            )
        return [dict(row) for row in rows]

    def _process_job(self, job: Dict[str, Any]) -> None:
        if job["status"] != "running":
            job = self._mark_running(job)

        if not self._endpoint_available or not self._http_client:
            self._mark_failed(job, TERMINAL_FAILURE_MESSAGE)
            return

        case_row = self._load_case(job["case_id"])
        if not case_row:
            self._mark_failed(job, "Case not found for docket enrichment.")
            return
        if not case_row.get("case_link"):
            self._mark_failed(job, "Case link missing; cannot request docket.")
            return

        try:
            fetch_result = self._fetch_docket_report(case_row)
        except Exception as exc:
            self._mark_failed(job, f"Docket request failed: {exc}")
            return

        if fetch_result.status_code != 200:
            self._mark_failed(
                job,
                f"Docket request returned status {fetch_result.status_code}.",
            )
            return

        docket_text, docket_entries, parsed_format = _extract_docket_payload(
            fetch_result.body,
            fetch_result.content_type,
            base_url=fetch_result.url,
        )
        raw_html = None
        if parsed_format == "html":
            raw_html = fetch_result.body.decode("utf-8", errors="replace")
        header_fields = _extract_docket_header_fields_from_html(raw_html) if raw_html else None
        if raw_html and _looks_like_login_redirect(raw_html):
            self._store_docket_payload(
                job,
                case_row,
                fetch_result,
                "",
                [],
                parsed_format,
                header_fields=header_fields,
                force_store_html=True,
                raw_html=raw_html,
            )
            self._mark_failed(
                job,
                _format_pacer_error(
                    "PACER login redirect; token expired or missing.",
                    fetch_result,
                ),
            )
            return
        if raw_html and _looks_like_docket_shell(raw_html):
            fetch_result = _with_form_details(fetch_result, raw_html)
            self._store_docket_payload(
                job,
                case_row,
                fetch_result,
                "",
                [],
                parsed_format,
                header_fields=header_fields,
                force_store_html=True,
                raw_html=raw_html,
            )
            self._mark_failed(
                job,
                _format_pacer_error(
                    "PACER returned a docket form instead of the docket report.",
                    fetch_result,
                ),
            )
            return
        if not job.get("include_docket_text"):
            docket_text = ""
            if docket_entries:
                for entry in docket_entries:
                    entry.pop("docketText", None)

        self._store_docket_payload(
            job,
            case_row,
            fetch_result,
            docket_text,
            docket_entries,
            parsed_format,
            header_fields=header_fields,
            raw_html=raw_html,
        )
        self._mark_completed(job)

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

    def _mark_completed(self, job: Dict[str, Any]) -> None:
        job_table = self._tables["docket_enrichment_jobs"]
        now = self._now()
        updates = {
            "status": "completed",
            "last_error": None,
            "finished_at": now,
        }
        with self._engine.begin() as conn:
            conn.execute(
                update(job_table)
                .where(job_table.c.id == job["id"])
                .values(**updates)
            )
        job.update(updates)

    def _load_case(self, case_id: int) -> Optional[Dict[str, Any]]:
        pcl_cases = self._tables["pcl_cases"]
        with self._engine.begin() as conn:
            row = (
                conn.execute(
                    select(
                        pcl_cases.c.id,
                        pcl_cases.c.court_id,
                        pcl_cases.c.case_office,
                        pcl_cases.c.case_year,
                        pcl_cases.c.case_type,
                        pcl_cases.c.case_number,
                        pcl_cases.c.case_number_full,
                        pcl_cases.c.case_link,
                        pcl_cases.c.case_title,
                        pcl_cases.c.short_title,
                    ).where(pcl_cases.c.id == case_id)
                )
                .mappings()
                .first()
            )
        return dict(row) if row else None

    def _fetch_docket_report(self, case_row: Dict[str, Any]) -> DocketFetchResult:
        case_id = _extract_case_id_from_url(case_row.get("case_link") or "")
        formatted_case_number = _format_case_number_for_pacer(
            case_office=case_row.get("case_office"),
            case_year=case_row.get("case_year"),
            case_type=case_row.get("case_type"),
            case_number=case_row.get("case_number"),
            case_number_full=case_row.get("case_number_full"),
        )
        _seed_case_cookies(
            self._http_client,
            case_id,
            case_row.get("case_number_full"),
            formatted_case_number=formatted_case_number,
        )
        _prime_case_session(self._http_client, case_row.get("case_link"))
        url = _build_docket_report_url(
            case_row["case_link"],
            case_number_full=case_row.get("case_number_full"),
            case_number=case_row.get("case_number"),
            output_format=self._docket_output,
            url_template=self._docket_url_template,
        )
        response = _request_with_login_retry(
            self._http_client,
            "GET",
            url,
            headers={"Accept": "application/xml, text/html"},
            include_cookie=True,
        )
        content_type = response.headers.get("Content-Type", "")
        if (
            response.status_code == 200
            and "html" in content_type.lower()
            and _looks_like_docket_shell(response.body.decode("utf-8", errors="replace"))
        ):
            submit = _submit_docket_form(
                self._http_client,
                response.body.decode("utf-8", errors="replace"),
                base_url=url,
                case_number_full=case_row.get("case_number_full"),
                case_number=case_row.get("case_number"),
                case_office=case_row.get("case_office"),
                case_year=case_row.get("case_year"),
                case_type=case_row.get("case_type"),
                preferred_output_format=self._docket_output,
            )
            if submit:
                if _looks_like_docket_shell(
                    submit.body.decode("utf-8", errors="replace")
                ):
                    forced = _force_docket_report(
                        self._http_client,
                        case_row["case_link"],
                        case_number_full=case_row.get("case_number_full"),
                    )
                    if forced:
                        return forced
                    multistep = _fetch_docket_report_multistep(
                        self._http_client,
                        case_row["case_link"],
                        case_number_full=case_row.get("case_number_full"),
                        case_office=case_row.get("case_office"),
                        case_year=case_row.get("case_year"),
                        case_type=case_row.get("case_type"),
                        case_number=case_row.get("case_number"),
                        output_format=self._docket_output,
                    )
                    if multistep:
                        if _looks_like_docket_shell(
                            multistep.body.decode("utf-8", errors="replace")
                        ):
                            alternate_output = (
                                "xml" if str(self._docket_output).lower() == "html" else "html"
                            )
                            multistep_html = _fetch_docket_report_multistep(
                                self._http_client,
                                case_row["case_link"],
                                case_number_full=case_row.get("case_number_full"),
                                case_office=case_row.get("case_office"),
                                case_year=case_row.get("case_year"),
                                case_type=case_row.get("case_type"),
                                case_number=case_row.get("case_number"),
                                output_format=alternate_output,
                            )
                            if multistep_html:
                                return multistep_html
                        return multistep
                    direct = _submit_docket_report_direct(
                        self._http_client,
                        case_row["case_link"],
                        case_id=_extract_case_id_from_url(case_row.get("case_link") or ""),
                        output_format="html",
                        all_case_ids=_extract_case_id_from_url(case_row.get("case_link") or ""),
                        case_num=formatted_case_number or " ",
                    )
                    if direct is not None and not _looks_like_docket_shell(
                        direct.body.decode("utf-8", errors="replace")
                    ):
                        return direct
                    direct_comma = _submit_docket_report_direct(
                        self._http_client,
                        case_row["case_link"],
                        case_id=_extract_case_id_from_url(case_row.get("case_link") or ""),
                        output_format="html",
                        all_case_ids=f"{_extract_case_id_from_url(case_row.get('case_link') or '')},",
                        case_num=formatted_case_number or " ",
                    )
                    if direct_comma is not None and not _looks_like_docket_shell(
                        direct_comma.body.decode("utf-8", errors="replace")
                    ):
                        return direct_comma
                return submit
            direct = _submit_docket_report_direct(
                self._http_client,
                case_row["case_link"],
                case_id=_extract_case_id_from_url(case_row.get("case_link") or ""),
                output_format="html",
                all_case_ids=_extract_case_id_from_url(case_row.get("case_link") or ""),
                case_num=formatted_case_number or " ",
            )
            if direct is not None and not _looks_like_docket_shell(
                direct.body.decode("utf-8", errors="replace")
            ):
                return direct
            direct_comma = _submit_docket_report_direct(
                self._http_client,
                case_row["case_link"],
                case_id=_extract_case_id_from_url(case_row.get("case_link") or ""),
                output_format="html",
                all_case_ids=f"{_extract_case_id_from_url(case_row.get('case_link') or '')},",
                case_num=formatted_case_number or " ",
            )
            if direct_comma is not None:
                return direct_comma
        return DocketFetchResult(
            url=url,
            status_code=response.status_code,
            content_type=content_type,
            body=response.body,
            headers=response.headers or {},
        )

    def _store_docket_payload(
        self,
        job: Dict[str, Any],
        case_row: Dict[str, Any],
        fetch_result: DocketFetchResult,
        docket_text: str,
        docket_entries: List[Dict[str, Any]],
        parsed_format: str,
        *,
        header_fields: Optional[Dict[str, Any]] = None,
        force_store_html: bool = False,
        raw_html: Optional[str] = None,
    ) -> None:
        pcl_cases = self._tables["pcl_cases"]
        pcl_case_fields = self._tables.get("pcl_case_fields")
        receipt_table = self._tables.get("docket_enrichment_receipts")
        now = self._now()
        docket_text_preview = _truncate_text(docket_text, 1000) if docket_text else ""
        html_body = raw_html
        if not html_body and parsed_format == "html":
            html_body = fetch_result.body.decode("utf-8", errors="replace")
        docket_is_shell = parsed_format == "html" and _looks_like_docket_shell(html_body or "")
        entry_count = len(docket_entries or [])
        recent_entries = _extract_recent_docket_entries_for_preview(docket_entries or [], limit=5)

        with self._engine.begin() as conn:
            if pcl_case_fields is not None:
                if docket_text and not docket_is_shell:
                    _upsert_case_field(
                        conn,
                        pcl_case_fields,
                        case_row["id"],
                        "docket_text",
                        field_value_text=None,
                        field_value_json={"text": docket_text},
                        now=now,
                    )
                    _upsert_case_field(
                        conn,
                        pcl_case_fields,
                        case_row["id"],
                        "docket_text_preview",
                        field_value_text=docket_text_preview,
                        field_value_json=None,
                        now=now,
                    )
                elif docket_text or force_store_html:
                    html_preview = _truncate_text(_strip_html(html_body or ""), 1000)
                    _upsert_case_field(
                        conn,
                        pcl_case_fields,
                        case_row["id"],
                        "docket_html",
                        field_value_text=None,
                        field_value_json={"text": html_body or docket_text},
                        now=now,
                    )
                    _upsert_case_field(
                        conn,
                        pcl_case_fields,
                        case_row["id"],
                        "docket_html_preview",
                        field_value_text=html_preview,
                        field_value_json=None,
                        now=now,
                    )
                _upsert_case_field(
                    conn,
                    pcl_case_fields,
                    case_row["id"],
                    "docket_entries",
                    field_value_text=None,
                    field_value_json=docket_entries if docket_entries else None,
                    now=now,
                )
                _upsert_case_field(
                    conn,
                    pcl_case_fields,
                    case_row["id"],
                    "docket_entry_count",
                    field_value_text=str(entry_count),
                    field_value_json=entry_count,
                    now=now,
                )
                _upsert_case_field(
                    conn,
                    pcl_case_fields,
                    case_row["id"],
                    "docket_recent_entries",
                    field_value_text=None,
                    field_value_json=recent_entries or None,
                    now=now,
                )
                _upsert_case_field(
                    conn,
                    pcl_case_fields,
                    case_row["id"],
                    "docket_source_url",
                    field_value_text=fetch_result.url,
                    field_value_json=None,
                    now=now,
                )
                _upsert_case_field(
                    conn,
                    pcl_case_fields,
                    case_row["id"],
                    "docket_content_type",
                    field_value_text=fetch_result.content_type,
                    field_value_json=None,
                    now=now,
                )
                _upsert_case_field(
                    conn,
                    pcl_case_fields,
                    case_row["id"],
                    "docket_fetched_at",
                    field_value_text=now.isoformat(),
                    field_value_json=None,
                    now=now,
                )
                _upsert_case_field(
                    conn,
                    pcl_case_fields,
                    case_row["id"],
                    "docket_payload_format",
                    field_value_text=parsed_format,
                    field_value_json=None,
                    now=now,
                )
                if force_store_html and html_body:
                    action, payload, _ = _select_docket_form(html_body)
                    if not action and not payload:
                        action, payload, _ = _select_any_form(html_body)
                    if action:
                        _upsert_case_field(
                            conn,
                            pcl_case_fields,
                            case_row["id"],
                            "docket_form_action",
                            field_value_text=_resolve_form_action(fetch_result.url, action),
                            field_value_json=None,
                            now=now,
                        )
                    if payload:
                        _upsert_case_field(
                            conn,
                            pcl_case_fields,
                            case_row["id"],
                            "docket_form_payload",
                            field_value_text=None,
                            field_value_json=_truncate_map(payload, 200),
                            now=now,
                        )
                if header_fields:
                    header_text = _flatten_header_fields(header_fields)
                    _upsert_case_field(
                        conn,
                        pcl_case_fields,
                        case_row["id"],
                        "docket_header_fields",
                        field_value_text=header_text or None,
                        field_value_json=header_fields,
                        now=now,
                    )
                    judges = _extract_judge_display_list(header_fields)
                    if judges:
                        _upsert_case_field(
                            conn,
                            pcl_case_fields,
                            case_row["id"],
                            "docket_judges",
                            field_value_text=" | ".join(judges),
                            field_value_json=judges,
                            now=now,
                        )
                        # Also backfill the normalized last name on the case record so the
                        # primary "Judge last name" filter works in list views.
                        existing_last = conn.execute(
                            select(pcl_cases.c.judge_last_name).where(pcl_cases.c.id == case_row["id"])
                        ).scalar_one_or_none()
                        if not (existing_last or "").strip():
                            last_name = _guess_last_name_from_judge_label(judges[0])
                            if last_name:
                                conn.execute(
                                    update(pcl_cases)
                                    .where(pcl_cases.c.id == case_row["id"])
                                    .values(judge_last_name=last_name, updated_at=now)
                                )
                    party_count = header_fields.get("party_count") if isinstance(header_fields, dict) else None
                    if isinstance(party_count, int):
                        _upsert_case_field(
                            conn,
                            pcl_case_fields,
                            case_row["id"],
                            "docket_party_count",
                            field_value_text=str(party_count),
                            field_value_json=party_count,
                            now=now,
                        )
                    attorney_count = header_fields.get("attorney_count") if isinstance(header_fields, dict) else None
                    if isinstance(attorney_count, int):
                        _upsert_case_field(
                            conn,
                            pcl_case_fields,
                            case_row["id"],
                            "docket_attorney_count",
                            field_value_text=str(attorney_count),
                            field_value_json=attorney_count,
                            now=now,
                        )
                parties = (
                    header_fields.get("parties")
                    if isinstance(header_fields, dict)
                    and isinstance(header_fields.get("parties"), list)
                    else []
                )
                case_entities = self._tables.get("case_entities")
                if header_fields and case_entities is not None:
                    try:
                        _refresh_case_entities(
                            conn,
                            case_entities,
                            case_id=case_row["id"],
                            header_fields=header_fields,
                        )
                    except Exception:
                        if self._logger:
                            self._logger.exception(
                                "Unable to refresh case_entities for case_id=%s",
                                case_row["id"],
                            )
                attorneys = _extract_attorneys_from_parties(parties) if parties else []
                party_summary = _flatten_parties_for_search(parties) if parties else ""
                # Keep these lists large enough that *all* counsel/party names remain searchable
                # and displayable on case cards. These are stored as JSON (not truncated), while
                # the text summary fields may be truncated for index safety.
                attorney_names = _extract_attorney_names(attorneys, limit=250) if attorneys else []
                party_names = _extract_party_names(parties, limit=250) if parties else []
                charge_items = _extract_charge_items_from_parties(parties, limit=40) if parties else []
                _upsert_case_field(
                    conn,
                    pcl_case_fields,
                    case_row["id"],
                    "docket_parties",
                    field_value_text=None,
                    field_value_json=parties or None,
                    now=now,
                )
                _upsert_case_field(
                    conn,
                    pcl_case_fields,
                    case_row["id"],
                    "docket_party_names",
                    field_value_text=" | ".join(party_names) if party_names else None,
                    field_value_json=party_names or None,
                    now=now,
                )
                _upsert_case_field(
                    conn,
                    pcl_case_fields,
                    case_row["id"],
                    "docket_attorneys",
                    field_value_text=None,
                    field_value_json=attorneys or None,
                    now=now,
                )
                _upsert_case_field(
                    conn,
                    pcl_case_fields,
                    case_row["id"],
                    "docket_party_summary",
                    field_value_text=party_summary or None,
                    field_value_json=None,
                    now=now,
                )
                _upsert_case_field(
                    conn,
                    pcl_case_fields,
                    case_row["id"],
                    "docket_attorney_names",
                    field_value_text=" | ".join(attorney_names) if attorney_names else None,
                    field_value_json=attorney_names or None,
                    now=now,
                )
                _upsert_case_field(
                    conn,
                    pcl_case_fields,
                    case_row["id"],
                    "docket_charges",
                    field_value_text=(
                        " | ".join(
                            f"{item.get('count')}{(' - ' + item.get('disposition')) if item.get('disposition') else ''}"
                            for item in charge_items
                            if isinstance(item, dict) and item.get("count")
                        )
                        if charge_items
                        else None
                    ),
                    field_value_json=charge_items or None,
                    now=now,
                )
                if fetch_result.request_debug and os.environ.get("PACER_DOCKET_DEBUG"):
                    _upsert_case_field(
                        conn,
                        pcl_case_fields,
                        case_row["id"],
                        "docket_request_debug",
                        field_value_text=None,
                        field_value_json=fetch_result.request_debug,
                        now=now,
                    )

            if receipt_table is not None:
                receipt_payload = {
                    "url": fetch_result.url,
                    "status_code": fetch_result.status_code,
                    "content_type": fetch_result.content_type,
                    "body_bytes": len(fetch_result.body),
                    "entry_count": len(docket_entries),
                    "include_docket_text": bool(job.get("include_docket_text")),
                    "fetched_at": now.isoformat(),
                }
                billable_pages = _extract_int_header(
                    fetch_result.headers,
                    [
                        "X-PACER-Billable-Pages",
                        "X-Billable-Pages",
                        "Billable-Pages",
                    ],
                )
                fee = _extract_int_header(
                    fetch_result.headers,
                    ["X-PACER-Search-Fee", "X-Search-Fee", "Search-Fee"],
                )
                if fetch_result.form_action:
                    receipt_payload["form_action"] = fetch_result.form_action
                if fetch_result.form_payload:
                    receipt_payload["form_payload"] = _truncate_map(
                        fetch_result.form_payload, 200
                    )
                if fetch_result.request_debug:
                    receipt_payload["request_debug"] = fetch_result.request_debug
                conn.execute(
                    receipt_table.insert().values(
                        job_id=job["id"],
                        receipt_json=json.dumps(receipt_payload),
                        billable_pages=billable_pages,
                        fee=fee,
                        description="PACER docket report",
                        client_code=None,
                    )
                )


def _build_docket_report_url(
    case_link: str,
    *,
    case_number_full: Optional[str],
    case_number: Optional[str],
    output_format: str,
    url_template: Optional[str],
) -> str:
    parsed = urlparse(case_link or "")
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("Invalid case link.")
    raw_query = parsed.query or ""
    case_id = None
    if raw_query.isdigit():
        case_id = raw_query
    elif raw_query:
        for token in raw_query.split("&"):
            if token.startswith("case_id="):
                case_id = token.split("=", 1)[1]
                break
    if not case_id:
        match = re.search(r"(\\d+)", raw_query)
        if match:
            case_id = match.group(1)
    if not case_id:
        raise ValueError("Case ID missing in case link.")

    host = parsed.netloc
    scheme = parsed.scheme
    if url_template:
        return url_template.format_map(
            {
                "case_id": case_id,
                "case_number_full": case_number_full or "",
                "case_number": case_number or "",
                "court_host": host,
                "scheme": scheme,
            }
        )

    base = f"{scheme}://{host}/cgi-bin/DktRpt.pl"
    params = {"case_id": case_id}
    if output_format:
        params["output"] = output_format
    return f"{base}?{urlencode(params)}"


def _prime_case_session(http_client: Any, case_link: Optional[str]) -> None:
    if not case_link:
        return
    try:
        http_client.request(
            "GET",
            case_link,
            headers={"Accept": "text/html"},
            include_cookie=True,
        )
    except Exception:
        return


def _seed_case_cookies(
    http_client: Any,
    case_id: Optional[str],
    case_number_full: Optional[str],
    formatted_case_number: Optional[str] = None,
) -> None:
    if not http_client:
        return
    setter = getattr(http_client, "set_cookie", None)
    if not callable(setter):
        return
    if case_id:
        setter("RECENT_CASES", f"{case_id};")
        setter("case_id", case_id)
    case_value = formatted_case_number or case_number_full
    if case_value:
        for name in ("case_num", "case_number", "CaseNumber", "caseNumber"):
            setter(name, case_value)
        if case_id:
            setter("CASE_NUM", f"{case_value}({case_id})")


def _extract_case_id_from_url(url: str) -> Optional[str]:
    parsed = urlparse(url)
    raw_query = parsed.query or ""
    if raw_query.isdigit():
        return raw_query
    for token in raw_query.split("&"):
        if token.startswith("case_id="):
            return token.split("=", 1)[1]
    match = re.search(r"(\\d+)", raw_query)
    return match.group(1) if match else None


def _extract_docket_payload(
    body: bytes,
    content_type: str,
    *,
    base_url: Optional[str] = None,
) -> tuple[str, List[Dict[str, Any]], str]:
    text = body.decode("utf-8", errors="replace")
    if "xml" in (content_type or "").lower() or text.lstrip().startswith("<"):
        try:
            return _extract_docket_xml(text), _extract_docket_entries(text), "xml"
        except ElementTree.ParseError:
            entries = _extract_docket_entries_from_html(text, base_url=base_url)
            return _extract_docket_text_from_entries(entries, text), entries, "html"
    entries = _extract_docket_entries_from_html(text, base_url=base_url)
    return _extract_docket_text_from_entries(entries, text), entries, "html"


def _extract_docket_entries_from_html(
    html_text: str, *, base_url: Optional[str] = None
) -> List[Dict[str, Any]]:
    try:
        tree = lxml_html.fromstring(html_text)
    except (ValueError, TypeError, lxml_etree.ParserError):
        return []

    rows = tree.xpath(
        "//table[.//text()[contains(., 'Docket Text')]]//tr"
    )
    if not rows:
        rows = tree.xpath(
            "//table[preceding-sibling::table[.//text()[contains(., 'Docket Text')]]]"
            "//tr"
        )

    entries: List[Dict[str, Any]] = []
    for row in rows:
        row_text = _normalize_html_text(row)
        lowered_row = row_text.lower()
        if ("docket text" in lowered_row and "date filed" in lowered_row) or (
            "docket text" in lowered_row and "filing date" in lowered_row
        ):
            continue
        cells = row.xpath("./td")
        if len(cells) < 3:
            continue
        date_filed = _normalize_html_text(cells[0])
        if not date_filed:
            continue
        doc_cell = cells[1]
        desc_cell = cells[2]
        if len(cells) >= 4:
            doc_cell = cells[2]
            desc_cell = cells[3]
        doc_number = _normalize_html_text(doc_cell)
        description = _normalize_html_text(desc_cell)
        links: List[Dict[str, str]] = []
        links.extend(_extract_links_from_cell(doc_cell, base_url=base_url))
        links.extend(_extract_links_from_cell(desc_cell, base_url=base_url))
        entry = {"dateFiled": date_filed, "description": description}
        if doc_number:
            entry["documentNumber"] = doc_number
        if links:
            entry["documentLinks"] = links
        entries.append(entry)
    return entries


def _extract_docket_text_from_entries(
    entries: List[Dict[str, Any]], fallback_html: str
) -> str:
    if not entries:
        return _strip_html(fallback_html)
    lines = []
    for entry in entries:
        date_filed = entry.get("dateFiled") or ""
        doc_number = entry.get("documentNumber") or ""
        description = entry.get("description") or ""
        parts = [part for part in [date_filed, doc_number, description] if part]
        if parts:
            lines.append(" | ".join(parts))
    return "\n".join(lines)


def _normalize_html_text(node: Any) -> str:
    text = " ".join(node.xpath(".//text()"))
    return re.sub(r"\s+", " ", text).strip()


def _extract_docket_entries(xml_text: str) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    root = ElementTree.fromstring(xml_text)
    for parent in root.iter():
        docket_text_nodes = [
            child
            for child in parent
            if child.tag.split("}")[-1] == "docketText"
        ]
        if not docket_text_nodes:
            continue
        docket_date = None
        for child in parent:
            if child.tag.split("}")[-1] == "docketTextDate":
                docket_date = (child.text or "").strip()
                break
        for node in docket_text_nodes:
            docket_text = (node.text or "").strip()
            entry = {"docketText": docket_text}
            if docket_date:
                entry["docketTextDate"] = docket_date
            entries.append(entry)
    return entries


def _extract_docket_xml(xml_text: str) -> str:
    root = ElementTree.fromstring(xml_text)
    parts = []
    for element in root.iter():
        tag = element.tag.split("}")[-1]
        if tag == "docketText":
            value = (element.text or "").strip()
            if value:
                parts.append(value)
    return "\n".join(parts)


def _strip_html(raw: str) -> str:
    if raw is None:
        return ""
    raw = str(raw)
    if not raw.strip():
        return ""
    try:
        tree = lxml_html.fromstring(raw)
    except (ValueError, TypeError, lxml_etree.ParserError):
        cleaned = re.sub(r"<script\\b[^>]*>.*?</script>", " ", raw, flags=re.IGNORECASE | re.DOTALL)
        cleaned = re.sub(r"<style\\b[^>]*>.*?</style>", " ", cleaned, flags=re.IGNORECASE | re.DOTALL)
        cleaned = re.sub(r"<noscript\\b[^>]*>.*?</noscript>", " ", cleaned, flags=re.IGNORECASE | re.DOTALL)
        cleaned = re.sub(r"<[^>]+>", " ", cleaned)
        cleaned = re.sub(r"\s+", " ", cleaned)
        return cleaned.strip()
    _drop_tags(tree, {"script", "style", "noscript", "head"})
    _insert_newlines(tree, {"br", "p", "div", "tr", "li"})
    text = tree.text_content()
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _drop_tags(tree: Any, tags: set[str]) -> None:
    for tag in tags:
        for node in tree.xpath(f"//{tag}"):
            node.drop_tree()


def _insert_newlines(tree: Any, tags: set[str]) -> None:
    for tag in tags:
        for node in tree.xpath(f"//{tag}"):
            node.tail = "\n" + (node.tail or "")


def _extract_links_from_cell(cell: Any, *, base_url: Optional[str]) -> List[Dict[str, Any]]:
    links: List[Dict[str, Any]] = []
    for anchor in cell.xpath(".//a"):
        href = (anchor.get("href") or "").strip()
        label = _normalize_html_text(anchor)
        onclick = (anchor.get("onclick") or "").strip()
        go_dls = None
        if onclick and "goDLS" in onclick:
            go_dls = _reverse_go_dls_function(onclick)
            if go_dls and base_url and go_dls.get("form_post_url"):
                go_dls["form_post_url"] = _resolve_link(
                    base_url, go_dls.get("form_post_url") or ""
                )
        if not href and go_dls and go_dls.get("form_post_url"):
            href = go_dls.get("form_post_url") or ""
        if href and base_url:
            href = _resolve_link(base_url, href)
        if not href and not go_dls:
            continue
        link: Dict[str, Any] = {}
        if href:
            link["href"] = href
        if label:
            link["label"] = label
        if go_dls:
            link["goDLS"] = go_dls
        links.append(link)
    return links


def _resolve_link(base_url: str, href: str) -> str:
    return urljoin(base_url, href)


def _reverse_go_dls_function(s: str) -> Optional[Dict[str, str]]:
    args = re.findall(r"'(.*?)'", s)
    if len(args) < 7:
        return None
    parts: Dict[str, str] = {
        "form_post_url": args[0],
        "caseid": args[1],
        "de_seq_num": args[2],
        "got_receipt": args[3],
        "pdf_header": args[4],
        "pdf_toggle_possible": args[5],
        "magic_num": args[6],
    }
    if len(args) >= 10:
        parts["claim_id"] = args[7]
        parts["claim_num"] = args[8]
        parts["claim_doc_seq"] = args[9]
    elif len(args) >= 8:
        parts["hdr"] = args[7]
    return parts


def _extract_docket_header_fields_from_html(html_text: str) -> Dict[str, Any]:
    if not html_text:
        return {}
    try:
        tree = lxml_html.fromstring(html_text)
    except (ValueError, TypeError, lxml_etree.ParserError):
        return {}
    header_fields: Dict[str, Any] = {}
    centers = tree.xpath("//center")
    for center in centers:
        lines = _extract_lines_from_node(center)
        if not lines:
            continue
        if any("date filed" in line.lower() for line in lines):
            header_fields.update(_parse_case_header_lines(lines))
            break
    judge_fields = _extract_judge_fields_from_text(_strip_html(html_text))
    header_fields.update(judge_fields)
    criteria = _extract_selection_criteria(tree)
    if criteria:
        header_fields["selection_criteria"] = criteria
    parties = _extract_party_sections(tree)
    if parties:
        header_fields["parties"] = parties
        header_fields["party_count"] = len(parties)
        header_fields["attorney_count"] = sum(
            len(party.get("represented_by") or []) for party in parties
        )
    return header_fields


_PARTY_SECTION_MAP = {
    "pending counts": "pending_counts",
    "terminated counts": "terminated_counts",
    "complaints": "complaints",
    "highest offense level (opening)": "highest_offense_level_opening",
    "highest offense level (terminated)": "highest_offense_level_terminated",
}

_PARTY_ROLE_PREFIXES = (
    "defendant",
    "plaintiff",
    "petitioner",
    "respondent",
    "appellant",
    "appellee",
    "movant",
    "claimant",
    "intervenor",
    "intervenor defendant",
    "crossclaim defendant",
    "cross claimant",
    "counter claimant",
    "debtor",
    "creditor",
    "trustee",
    "garnishee",
    "interested party",
    "in re",
)


def _extract_party_sections(tree: Any) -> List[Dict[str, Any]]:
    rows = tree.xpath("//tr")
    if not rows:
        return []
    parties: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    active_section: Optional[str] = None
    for row in rows:
        row_text = _normalize_html_text(row)
        lowered_row = row_text.lower()
        if ("docket text" in lowered_row and "date filed" in lowered_row) or (
            "docket text" in lowered_row and "#" in lowered_row
        ):
            break
        section_heading = _extract_party_section_heading(row)
        if section_heading:
            if current is not None:
                active_section = section_heading
            continue
        party_heading = _extract_party_heading(row)
        if party_heading:
            if current is not None:
                finalized = _finalize_party_section(current)
                if finalized:
                    parties.append(finalized)
            current = _new_party_section(party_heading)
            active_section = None
            continue
        if current is None:
            continue

        represented_by_index = _represented_by_index(row)
        if represented_by_index is not None:
            _apply_represented_by_row(current, row, represented_by_index)
            continue

        if active_section in {"pending_counts", "terminated_counts", "complaints"}:
            item = _extract_disposition_row(row)
            if item:
                current[active_section].append(item)
            continue

        if active_section in {
            "highest_offense_level_opening",
            "highest_offense_level_terminated",
        }:
            value = _extract_first_cell_text(row)
            if value:
                current[active_section] = value
                active_section = None
            continue

        _merge_party_identity(current, row)

    if current is not None:
        finalized = _finalize_party_section(current)
        if finalized:
            parties.append(finalized)
    return parties


def _extract_party_heading(row: Any) -> Optional[str]:
    underlined = [_normalize_html_text(node) for node in row.xpath(".//u")]
    for label in underlined:
        normalized = _normalize_party_label(label)
        if not normalized:
            continue
        if normalized in _PARTY_SECTION_MAP:
            continue
        if normalized == "disposition":
            continue
        if normalized.startswith("highest offense level"):
            continue
        if re.search(r"\(\d+\)\s*$", normalized):
            return label
        if any(normalized.startswith(prefix) for prefix in _PARTY_ROLE_PREFIXES):
            return label
    return None


def _extract_party_section_heading(row: Any) -> Optional[str]:
    underlined = [_normalize_html_text(node) for node in row.xpath(".//u")]
    for label in underlined:
        normalized = _normalize_party_label(label)
        if normalized in _PARTY_SECTION_MAP:
            return _PARTY_SECTION_MAP[normalized]
    return None


def _normalize_party_label(value: str) -> str:
    return re.sub(r"\s+", " ", (value or "").replace("\xa0", " ")).strip().lower()


def _new_party_section(heading: str) -> Dict[str, Any]:
    cleaned_heading = re.sub(r"\s+", " ", heading).strip()
    party_type = cleaned_heading
    party_index: Optional[int] = None
    match = re.match(r"(.+?)\s*\((\d+)\)\s*$", cleaned_heading)
    if match:
        party_type = match.group(1).strip()
        party_index = int(match.group(2))
    return {
        "party_heading": cleaned_heading,
        "party_type": party_type,
        "party_index": party_index,
        "name": None,
        "aliases": [],
        "details": [],
        "represented_by": [],
        "pending_counts": [],
        "terminated_counts": [],
        "complaints": [],
        "highest_offense_level_opening": None,
        "highest_offense_level_terminated": None,
    }


def _represented_by_index(row: Any) -> Optional[int]:
    cells = row.xpath("./td")
    for index, cell in enumerate(cells):
        lowered = _normalize_html_text(cell).lower().replace("\xa0", " ")
        if "represented by" in lowered:
            return index
    return None


def _apply_represented_by_row(
    party: Dict[str, Any], row: Any, represented_by_index: int
) -> None:
    cells = row.xpath("./td")
    if not cells:
        return
    left_index = represented_by_index - 1 if represented_by_index > 0 else 0
    left_cell = cells[left_index] if left_index < len(cells) else None
    right_index = represented_by_index + 1
    right_cell = cells[right_index] if right_index < len(cells) else None
    if left_cell is not None:
        name, details = _extract_party_name_and_details(left_cell)
        _merge_party_name(party, name)
        _merge_unique_list(party["details"], details)
    if right_cell is not None:
        attorneys = _extract_attorneys_from_cell(right_cell)
        _merge_attorneys(party["represented_by"], attorneys)


def _extract_party_name_and_details(cell: Any) -> tuple[Optional[str], List[str]]:
    lines = [
        line
        for line in _extract_lines_from_node(cell)
        if "represented by" not in line.lower()
    ]
    if not lines:
        return None, []
    bold_names = [_normalize_html_text(node) for node in cell.xpath(".//b")]
    name = bold_names[0] if bold_names else lines[0]
    details = [line for line in lines if line != name]
    return name or None, details


def _extract_attorneys_from_cell(cell: Any) -> List[Dict[str, Any]]:
    raw_html = lxml_html.tostring(cell, encoding="unicode")
    # Use a word boundary so we don't treat <br> / <body> as <b>.
    segments = re.split(r"(?i)<b\\b[^>]*>", raw_html)
    attorneys: List[Dict[str, Any]] = []
    for segment in segments[1:]:
        name_html, closing, body_html = segment.partition("</b>")
        if not closing:
            continue
        name = re.sub(r"\s+", " ", _strip_html(name_html)).strip()
        if not name:
            continue
        # `body_html` is often an HTML fragment beginning with `<br>`; wrap so we
        # don't lose tail text when parsing with lxml.
        lines = _split_nonempty_lines(_strip_html(f"<div>{body_html}</div>"))
        attorneys.append(_build_attorney_record(name, lines))
    line_attorneys = _extract_attorneys_from_lines(
        _split_nonempty_lines(_strip_html(raw_html))
    )
    if attorneys and line_attorneys:
        _merge_attorneys(attorneys, line_attorneys)
        return attorneys
    if attorneys:
        return attorneys
    if line_attorneys:
        return line_attorneys
    return []


def _split_nonempty_lines(text: str) -> List[str]:
    lines: List[str] = []
    for line in text.splitlines():
        cleaned = re.sub(r"\s+", " ", line).strip()
        if cleaned:
            lines.append(cleaned)
    return lines


def _extract_attorneys_from_lines(lines: List[str]) -> List[Dict[str, Any]]:
    if not lines:
        return []
    records: List[Dict[str, Any]] = []
    current_name: Optional[str] = None
    current_lines: List[str] = []
    for line in lines:
        if _looks_like_attorney_name_line(line):
            if current_name:
                records.append(_build_attorney_record(current_name, current_lines))
            current_name = line
            current_lines = []
            continue
        if current_name:
            current_lines.append(line)
    if current_name:
        records.append(_build_attorney_record(current_name, current_lines))
    return records


_ATTORNEY_NON_NAME_TOKENS = {
    "law",
    "firm",
    "office",
    "offices",
    "group",
    "department",
    "division",
    "justice",
    "court",
    "suite",
    "street",
    "st",
    "avenue",
    "ave",
    "road",
    "rd",
    "drive",
    "dr",
    "blvd",
    "boulevard",
    "room",
    "floor",
    "box",
    "u.s",
    "us",
    "federal",
    "attorney",
    "attorneys",
}


def _looks_like_attorney_name_line(value: str) -> bool:
    normalized = re.sub(r"\s+", " ", (value or "")).strip()
    if not normalized:
        return False
    lowered = normalized.lower()
    if lowered.startswith(
        (
            "designation:",
            "email:",
            "e-mail:",
            "phone:",
            "telephone:",
            "tel:",
            "ph:",
            "fax:",
            "facsimile:",
            "bar status:",
            "terminated:",
            "website:",
            "web:",
        )
    ):
        return False
    if "@" in normalized:
        return False
    if re.search(r"(?i)\b(?:https?://|www\.)", normalized):
        return False
    candidate = re.sub(r"(?i)\bterminated\b.*$", "", normalized).strip(" ,;:-")
    if not candidate:
        return False
    if any(char.isdigit() for char in candidate):
        return False
    tokens = [token for token in re.split(r"\s+", candidate) if token]
    if len(tokens) < 2 or len(tokens) > 6:
        return False
    clean_tokens: List[str] = []
    for token in tokens:
        cleaned = re.sub(r"[^A-Za-z'.-]", "", token)
        if not cleaned:
            return False
        clean_tokens.append(cleaned)
    if not all(token[0].isalpha() and token[0].isupper() for token in clean_tokens):
        return False
    lowered_tokens = {token.lower().strip(".") for token in clean_tokens}
    if lowered_tokens & _ATTORNEY_NON_NAME_TOKENS:
        return False
    return True


def _build_attorney_record(name: str, lines: List[str]) -> Dict[str, Any]:
    attorney: Dict[str, Any] = {"name": name}
    raw_lines: List[str] = []
    details: List[str] = []
    emails: List[str] = []
    phones: List[str] = []
    faxes: List[str] = []
    websites: List[str] = []
    designations: List[str] = []
    roles: List[str] = []
    for line in lines:
        normalized = re.sub(r"\s+", " ", line).strip()
        if not normalized:
            continue
        raw_lines.append(normalized)
        lowered = normalized.lower()
        for match in re.findall(r"(?i)(https?://[^\s,;]+|www\.[^\s,;]+)", normalized):
            cleaned_url = match.rstrip(".,;)")
            if cleaned_url:
                websites.append(cleaned_url)
        email_matches = re.findall(
            r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}",
            normalized,
            flags=re.IGNORECASE,
        )
        if lowered.startswith(("email:", "e-mail:", "email ")) or email_matches:
            values = email_matches
            if not values and ":" in normalized:
                candidate = normalized.split(":", 1)[1].strip()
                if candidate:
                    values = [candidate]
            for value in values:
                cleaned_email = value.strip(".,; ")
                if cleaned_email:
                    emails.append(cleaned_email)
            continue
        phone_match = re.match(
            r"(?i)^(?:phone|telephone|tel|ph)\b[:\s.-]*(.+)$", normalized
        )
        if phone_match:
            value = phone_match.group(1).strip()
            if value:
                phones.extend(_extract_phone_candidates(value) or [value])
            continue
        fax_match = re.match(r"(?i)^(?:fax|facsimile)\b[:\s.-]*(.+)$", normalized)
        if fax_match:
            value = fax_match.group(1).strip()
            if value:
                faxes.extend(_extract_phone_candidates(value) or [value])
            continue
        if lowered.startswith(("http://", "https://", "www.")):
            websites.append(normalized)
            continue
        if lowered.startswith(("website:", "web:")):
            value = normalized.split(":", 1)[1].strip() if ":" in normalized else ""
            if value:
                matches = re.findall(r"(?i)(https?://[^\s,;]+|www\.[^\s,;]+)", value)
                if matches:
                    for match in matches:
                        websites.append(match.rstrip(".,;)"))
                else:
                    websites.append(value)
            continue
        if lowered.startswith("designation:"):
            value = normalized.split(":", 1)[1].strip()
            if value:
                designations.append(value)
            continue
        if "attorney" in lowered and normalized.upper() == normalized:
            roles.append(normalized)
            continue
        if _looks_like_phone_line(normalized):
            phones.extend(_extract_phone_candidates(normalized) or [normalized])
            continue
        details.append(normalized)
    if raw_lines:
        attorney["raw_lines"] = _unique_list(raw_lines)
    if details:
        attorney["details"] = _unique_list(details)
        attorney["organization"] = _pick_organization_line(attorney["details"])
    if emails:
        attorney["emails"] = _unique_list(emails)
    if phones:
        attorney["phones"] = _unique_list(phones)
    if faxes:
        attorney["faxes"] = _unique_list(faxes)
    if websites:
        attorney["websites"] = _unique_list(websites)
    if designations:
        attorney["designations"] = _unique_list(designations)
    if roles:
        attorney["roles"] = _unique_list(roles)
    return attorney


def _extract_phone_candidates(value: str) -> List[str]:
    if not value:
        return []
    matches = re.findall(
        r"(?:\+?1[\s.-]*)?(?:\(\d{3}\)|\d{3})[\s.-]*\d{3}[\s.-]*\d{4}(?:\s*(?:x|ext\.?)\s*\d+)?|\d{3}[\s.-]\d{4}",
        value,
        flags=re.IGNORECASE,
    )
    return _unique_list(matches)


def _pick_organization_line(details: List[str]) -> str:
    if not details:
        return ""
    for line in details:
        lowered = line.lower()
        if any(char.isdigit() for char in line):
            continue
        if lowered.startswith(
            (
                "designation:",
                "email:",
                "phone:",
                "telephone:",
                "tel:",
                "ph:",
                "fax:",
                "facsimile:",
                "website:",
                "web:",
            )
        ):
            continue
        if _looks_like_attorney_name_line(line):
            continue
        return line
    return details[0]


def _looks_like_phone_line(value: str) -> bool:
    if not value:
        return False
    if "@" in value:
        return False
    if _extract_phone_candidates(value):
        return True
    if re.search(r"\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}", value):
        return True
    if re.fullmatch(r"\d{3}[-.\s]\d{4}", value):
        return True
    return False


def _merge_attorneys(
    existing: List[Dict[str, Any]], new_attorneys: List[Dict[str, Any]]
) -> None:
    for candidate in new_attorneys:
        key = _attorney_key(candidate)
        matched = None
        for attorney in existing:
            if _attorney_key(attorney) == key:
                matched = attorney
                break
        if matched is None:
            existing.append(candidate)
            continue
        for field in (
            "raw_lines",
            "details",
            "emails",
            "phones",
            "faxes",
            "websites",
            "designations",
            "roles",
        ):
            _merge_unique_list(matched.setdefault(field, []), candidate.get(field) or [])
        if not matched.get("organization") and candidate.get("organization"):
            matched["organization"] = candidate["organization"]


def _attorney_key(attorney: Dict[str, Any]) -> tuple[str, str]:
    name = str(attorney.get("name") or "").strip().lower()
    emails = ",".join(
        sorted(
            str(value).strip().lower()
            for value in (attorney.get("emails") or [])
            if str(value).strip()
        )
    )
    return (name, emails)


def _extract_disposition_row(row: Any) -> Optional[Dict[str, str]]:
    cells = row.xpath("./td")
    if not cells:
        return None
    count_text = _normalize_html_text(cells[0]) if len(cells) >= 1 else ""
    disposition = _normalize_html_text(cells[2]) if len(cells) >= 3 else ""
    normalized_count = _normalize_party_label(count_text)
    if normalized_count in _PARTY_SECTION_MAP or normalized_count == "disposition":
        return None
    if not count_text and not disposition:
        return None
    return {"count": count_text, "disposition": disposition}


def _extract_first_cell_text(row: Any) -> Optional[str]:
    cells = row.xpath("./td")
    if not cells:
        return None
    value = _normalize_html_text(cells[0])
    normalized = _normalize_party_label(value)
    if not value:
        return None
    if normalized in _PARTY_SECTION_MAP or normalized == "disposition":
        return None
    return value


def _merge_party_identity(party: Dict[str, Any], row: Any) -> None:
    cells = row.xpath("./td")
    if not cells:
        return
    first_cell = cells[0]
    name, details = _extract_party_name_and_details(first_cell)
    _merge_party_name(party, name)
    _merge_unique_list(party["details"], details)


def _merge_party_name(party: Dict[str, Any], name: Optional[str]) -> None:
    if not name:
        return
    cleaned = re.sub(r"\s+", " ", name).strip()
    if not cleaned:
        return
    existing_name = party.get("name")
    if not existing_name:
        party["name"] = cleaned
        return
    if cleaned == existing_name:
        return
    aliases = party.setdefault("aliases", [])
    if cleaned not in aliases:
        aliases.append(cleaned)


def _merge_unique_list(target: List[str], values: List[str]) -> None:
    for value in values:
        cleaned = re.sub(r"\s+", " ", str(value)).strip()
        if cleaned and cleaned not in target:
            target.append(cleaned)


def _unique_list(values: List[str]) -> List[str]:
    output: List[str] = []
    for value in values:
        cleaned = re.sub(r"\s+", " ", str(value)).strip()
        if cleaned and cleaned not in output:
            output.append(cleaned)
    return output


def _finalize_party_section(party: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if party.get("party_index") is None:
        party.pop("party_index", None)
    if not party.get("aliases"):
        party.pop("aliases", None)
    if not party.get("details"):
        party.pop("details", None)
    if not party.get("represented_by"):
        party.pop("represented_by", None)
    for key in ("pending_counts", "terminated_counts", "complaints"):
        items = [item for item in (party.get(key) or []) if item.get("count") or item.get("disposition")]
        if items:
            party[key] = items
        else:
            party.pop(key, None)
    if not party.get("highest_offense_level_opening"):
        party.pop("highest_offense_level_opening", None)
    if not party.get("highest_offense_level_terminated"):
        party.pop("highest_offense_level_terminated", None)
    if not party.get("name") and not party.get("represented_by"):
        return None
    return party


def _extract_lines_from_node(node: Any) -> List[str]:
    try:
        copied = lxml_html.fromstring(lxml_html.tostring(node))
    except Exception:
        text = " ".join(node.xpath(".//text()"))
        return [re.sub(r"\s+", " ", text).strip()] if text.strip() else []
    _insert_newlines(copied, {"br"})
    text = copied.text_content()
    lines = []
    for line in text.splitlines():
        cleaned = re.sub(r"\s+", " ", line).strip()
        if cleaned:
            lines.append(cleaned)
    return lines


def _parse_case_header_lines(lines: List[str]) -> Dict[str, Any]:
    header: Dict[str, Any] = {}
    if lines:
        header["case_number_header"] = lines[0]
    if len(lines) > 1:
        header["case_title"] = lines[1]
    for line in lines[2:]:
        lowered = line.lower()
        if "date filed" in lowered:
            header["date_filed"] = _extract_value_after_label(line, "Date filed:")
        if "date of last filing" in lowered:
            header["date_last_filing"] = _extract_value_after_label(
                line, "Date of last filing:"
            )
        if "presiding" in lowered or "assigned" in lowered or "judge" in lowered:
            header["judge_line"] = line
    return header


def _extract_judge_fields_from_text(text: str) -> Dict[str, Any]:
    if not text:
        return {}
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    assigned: List[str] = []
    referred: List[str] = []
    presiding: List[str] = []
    for line in lines:
        match = re.search(r"Assigned to:\s*(.+)", line, re.IGNORECASE)
        if match:
            assigned.append(match.group(1).strip())
            continue
        # Some courts render this as "ASSIGNED JUDGES <judge label>" (no colon).
        match = re.search(r"Assigned Judges?:\s*(.+)", line, re.IGNORECASE)
        if not match:
            match = re.search(r"Assigned Judges?\s+(.+)", line, re.IGNORECASE)
        if match:
            assigned.append(match.group(1).strip())
            continue
        match = re.search(r"Referred to:\s*(.+)", line, re.IGNORECASE)
        if match:
            referred.append(match.group(1).strip())
            continue
        match = re.search(r"Presiding Judge:\s*(.+)", line, re.IGNORECASE)
        if match:
            presiding.append(match.group(1).strip())
            continue
    judges = []
    for value in assigned + referred + presiding:
        if value and value not in judges:
            judges.append(value)
    output: Dict[str, Any] = {}
    if assigned:
        output["assigned_to"] = assigned
    if referred:
        output["referred_to"] = referred
    if presiding:
        output["presiding_judge"] = presiding
    if judges:
        output["judges"] = judges
    return output


def _extract_value_after_label(text: str, label: str) -> Optional[str]:
    if label.lower() not in text.lower():
        return None
    parts = re.split(label, text, flags=re.IGNORECASE)
    if len(parts) < 2:
        return None
    value = parts[1].strip()
    return value or None


def _extract_selection_criteria(tree: Any) -> Dict[str, str]:
    criteria: Dict[str, str] = {}
    headers = tree.xpath(
        "//h3[contains(translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'selection criteria for query')]"
    )
    if not headers:
        return criteria
    header = headers[0]
    table = header.getparent().xpath(".//table")[0] if header.getparent().xpath(".//table") else None
    if table is None:
        return criteria
    rows = table.xpath(".//tr")
    for row in rows:
        cells = row.xpath("./td")
        if len(cells) < 2:
            continue
        key = _normalize_html_text(cells[0]).strip(":")
        value = _normalize_html_text(cells[1])
        if key and value:
            criteria[key] = value
    return criteria


def _flatten_header_fields(header_fields: Dict[str, Any]) -> str:
    if not header_fields:
        return ""
    parts: List[str] = []
    for key in ("case_number_header", "case_title", "judge_line", "date_filed", "date_last_filing"):
        value = header_fields.get(key)
        if value:
            parts.append(str(value))
    for key in ("assigned_to", "referred_to", "presiding_judge"):
        value = header_fields.get(key)
        if isinstance(value, list):
            for item in value:
                parts.append(str(item))
        elif value:
            parts.append(str(value))
    selection = header_fields.get("selection_criteria")
    if isinstance(selection, dict):
        for key, value in selection.items():
            parts.append(f"{key}: {value}")
    parties = header_fields.get("parties")
    if isinstance(parties, list):
        for party in parties:
            if not isinstance(party, dict):
                continue
            label = party.get("party_heading") or party.get("party_type")
            name = party.get("name")
            if label and name:
                parts.append(f"{label}: {name}")
            elif label:
                parts.append(str(label))
            for attorney in party.get("represented_by") or []:
                attorney_name = attorney.get("name") if isinstance(attorney, dict) else None
                if attorney_name:
                    parts.append(f"Counsel: {attorney_name}")
            for key in ("pending_counts", "terminated_counts", "complaints"):
                for item in party.get(key) or []:
                    if not isinstance(item, dict):
                        continue
                    count_value = item.get("count")
                    disposition = item.get("disposition")
                    if count_value:
                        parts.append(str(count_value))
                    if disposition:
                        parts.append(str(disposition))
    return " | ".join(parts)


def _extract_judge_display_list(header_fields: Dict[str, Any]) -> List[str]:
    if not isinstance(header_fields, dict):
        return []
    values: List[str] = []
    for key in ("assigned_to", "presiding_judge", "referred_to", "judges"):
        raw = header_fields.get(key)
        if isinstance(raw, list):
            for item in raw:
                cleaned = re.sub(r"\s+", " ", str(item or "")).strip()
                cleaned = _format_judge_label_for_display(cleaned)
                if cleaned:
                    values.append(cleaned)
        elif raw:
            cleaned = re.sub(r"\s+", " ", str(raw)).strip()
            cleaned = _format_judge_label_for_display(cleaned)
            if cleaned:
                values.append(cleaned)
    seen = set()
    deduped: List[str] = []
    for value in values:
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(value)
    return deduped


_JUDGE_SUFFIXES = {"jr", "sr", "ii", "iii", "iv", "v"}


def _format_judge_label_for_display(value: str) -> str:
    if not value:
        return ""
    cleaned = re.sub(r"\s+", " ", str(value)).strip()
    cleaned = re.sub(r"\s*\\([^)]*\\)\\s*$", "", cleaned).strip()
    # Remove common prefixes so the case card can show just the full name.
    cleaned = re.sub(
        r"(?i)^(?:hon\\.?\\s+)?(?:chief\\s+)?(?:district|magistrate|bankruptcy)?\\s*judge\\s+",
        "",
        cleaned,
    ).strip()
    if not cleaned:
        return ""

    letters = [ch for ch in cleaned if ch.isalpha()]
    uppercase_ratio = (
        (sum(1 for ch in letters if ch.isupper()) / len(letters)) if letters else 0.0
    )
    if uppercase_ratio >= 0.85:
        cleaned = cleaned.title()
        # Fix common titlecasing issues like "Mchugh" -> "McHugh".
        cleaned = re.sub(
            r"\bMc([a-z])",
            lambda match: f"Mc{match.group(1).upper()}",
            cleaned,
        )
        # Restore suffix casing (Jr., Sr., II, III, IV, V).
        tokens = cleaned.split()
        normalized_tokens: List[str] = []
        for token in tokens:
            bare = token.strip(",.;:")
            lower = bare.lower().strip(".")
            if lower in _JUDGE_SUFFIXES:
                # Keep original punctuation if any.
                suffix = lower.upper() if lower in {"ii", "iii", "iv", "v"} else lower.title()
                prefix = token[: token.find(bare)] if bare in token else ""
                suffix_token = token.replace(bare, suffix)
                normalized_tokens.append(suffix_token if suffix_token else suffix)
            else:
                normalized_tokens.append(token)
        cleaned = " ".join(normalized_tokens)

    return cleaned


def _guess_last_name_from_judge_label(value: str) -> str:
    if not value:
        return ""
    cleaned = re.sub(r"\s+", " ", str(value)).strip()
    cleaned = re.sub(r"\s*\\([^)]*\\)\\s*$", "", cleaned).strip()
    cleaned = re.sub(
        r"(?i)^(?:hon\\.?\\s+)?(?:chief\\s+)?(?:district|magistrate|bankruptcy)?\\s*judge\\s+",
        "",
        cleaned,
    ).strip()
    if not cleaned:
        return ""
    tokens = [token.strip(" ,.;:") for token in cleaned.split() if token.strip(" ,.;:")]
    if len(tokens) < 1:
        return ""
    last = tokens[-1]
    if last.lower().strip(".") in _JUDGE_SUFFIXES and len(tokens) >= 2:
        last = tokens[-2]
    return last.strip(" ,.;:")[:80]


def backfill_case_card_metadata_from_saved_dockets(
    engine: Any,
    tables: Dict[str, Table],
    *,
    limit: int = 500,
) -> Dict[str, int]:
    """Populate case-card metadata using already-saved docket header fields.

    This is a *local* operation (no PACER calls). It scans cases that already have
    `docket_header_fields` stored and writes derived fields that make the case-card
    UI useful:
    - `docket_judges` (list of judge labels)
    - `docket_party_count` (int)
    - `docket_attorney_count` (int)
    - `docket_parties` / `docket_attorneys` / `docket_party_summary` (for counsel directory)
    - Backfills `pcl_cases.judge_last_name` when missing so judge filters work.

    Returns:
      dict with keys: scanned, updated_fields, updated_cases
    """

    pcl_cases = tables["pcl_cases"]
    pcl_case_fields = tables.get("pcl_case_fields")
    if pcl_case_fields is None:
        return {"scanned": 0, "updated_fields": 0, "updated_cases": 0}
    case_entities = tables.get("case_entities")
    if case_entities is not None:
        try:
            inspector = inspect(engine)
            if not inspector.has_table(case_entities.name):
                case_entities = None
        except Exception:
            case_entities = None

    header = pcl_case_fields.alias("header_fields")
    docket_judges_row = pcl_case_fields.alias("docket_judges_row")
    docket_party_count_row = pcl_case_fields.alias("docket_party_count_row")
    docket_attorney_count_row = pcl_case_fields.alias("docket_attorney_count_row")
    docket_parties_row = pcl_case_fields.alias("docket_parties_row")
    docket_party_names_row = pcl_case_fields.alias("docket_party_names_row")
    docket_attorneys_row = pcl_case_fields.alias("docket_attorneys_row")
    docket_party_summary_row = pcl_case_fields.alias("docket_party_summary_row")
    docket_entries_row = pcl_case_fields.alias("docket_entries_row")
    docket_entry_count_row = pcl_case_fields.alias("docket_entry_count_row")
    docket_recent_entries_row = pcl_case_fields.alias("docket_recent_entries_row")
    docket_attorney_names_row = pcl_case_fields.alias("docket_attorney_names_row")
    docket_charges_row = pcl_case_fields.alias("docket_charges_row")

    join_from = (
        pcl_cases.join(
            header,
            (header.c.case_id == pcl_cases.c.id)
            & (header.c.field_name == "docket_header_fields"),
        )
        .outerjoin(
            docket_judges_row,
            (docket_judges_row.c.case_id == pcl_cases.c.id)
            & (docket_judges_row.c.field_name == "docket_judges"),
        )
        .outerjoin(
            docket_party_count_row,
            (docket_party_count_row.c.case_id == pcl_cases.c.id)
            & (docket_party_count_row.c.field_name == "docket_party_count"),
        )
        .outerjoin(
            docket_attorney_count_row,
            (docket_attorney_count_row.c.case_id == pcl_cases.c.id)
            & (docket_attorney_count_row.c.field_name == "docket_attorney_count"),
        )
        .outerjoin(
            docket_parties_row,
            (docket_parties_row.c.case_id == pcl_cases.c.id)
            & (docket_parties_row.c.field_name == "docket_parties"),
        )
        .outerjoin(
            docket_party_names_row,
            (docket_party_names_row.c.case_id == pcl_cases.c.id)
            & (docket_party_names_row.c.field_name == "docket_party_names"),
        )
        .outerjoin(
            docket_attorneys_row,
            (docket_attorneys_row.c.case_id == pcl_cases.c.id)
            & (docket_attorneys_row.c.field_name == "docket_attorneys"),
        )
        .outerjoin(
            docket_party_summary_row,
            (docket_party_summary_row.c.case_id == pcl_cases.c.id)
            & (docket_party_summary_row.c.field_name == "docket_party_summary"),
        )
        .outerjoin(
            docket_entries_row,
            (docket_entries_row.c.case_id == pcl_cases.c.id)
            & (docket_entries_row.c.field_name == "docket_entries"),
        )
        .outerjoin(
            docket_entry_count_row,
            (docket_entry_count_row.c.case_id == pcl_cases.c.id)
            & (docket_entry_count_row.c.field_name == "docket_entry_count"),
        )
        .outerjoin(
            docket_recent_entries_row,
            (docket_recent_entries_row.c.case_id == pcl_cases.c.id)
            & (docket_recent_entries_row.c.field_name == "docket_recent_entries"),
        )
        .outerjoin(
            docket_attorney_names_row,
            (docket_attorney_names_row.c.case_id == pcl_cases.c.id)
            & (docket_attorney_names_row.c.field_name == "docket_attorney_names"),
        )
        .outerjoin(
            docket_charges_row,
            (docket_charges_row.c.case_id == pcl_cases.c.id)
            & (docket_charges_row.c.field_name == "docket_charges"),
        )
    )

    stmt = (
        select(
            pcl_cases.c.id.label("case_id"),
            pcl_cases.c.judge_last_name,
            header.c.field_value_json.label("header_fields"),
            docket_entries_row.c.field_value_json.label("docket_entries"),
        )
        .select_from(join_from)
        .where(
            or_(
                docket_judges_row.c.id.is_(None),
                docket_party_count_row.c.id.is_(None),
                docket_attorney_count_row.c.id.is_(None),
                docket_parties_row.c.id.is_(None),
                docket_party_names_row.c.id.is_(None),
                docket_party_names_row.c.field_value_json.is_(None),
                docket_attorneys_row.c.id.is_(None),
                docket_party_summary_row.c.id.is_(None),
                docket_entry_count_row.c.id.is_(None),
                docket_entry_count_row.c.field_value_json.is_(None),
                docket_recent_entries_row.c.id.is_(None),
                docket_recent_entries_row.c.field_value_json.is_(None),
                docket_attorney_names_row.c.id.is_(None),
                docket_attorney_names_row.c.field_value_json.is_(None),
                docket_charges_row.c.id.is_(None),
                docket_charges_row.c.field_value_json.is_(None),
                pcl_cases.c.judge_last_name.is_(None),
                pcl_cases.c.judge_last_name == "",
            )
        )
        .order_by(pcl_cases.c.id.asc())
    )
    if isinstance(limit, int) and limit > 0:
        stmt = stmt.limit(limit)

    def _coerce_header_fields(value: Any) -> Optional[Dict[str, Any]]:
        if value is None:
            return None
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            raw = value.strip()
            if not raw:
                return None
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                return None
            return parsed if isinstance(parsed, dict) else None
        return None

    def _coerce_docket_entries(value: Any) -> List[Dict[str, Any]]:
        if value is None:
            return []
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, str):
            raw = value.strip()
            if not raw:
                return []
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                return []
            if isinstance(parsed, list):
                return [item for item in parsed if isinstance(item, dict)]
        return []

    now = datetime.utcnow()
    scanned = 0
    updated_fields = 0
    updated_cases = 0

    with engine.begin() as conn:
        rows = conn.execute(stmt).mappings().all()
        for row in rows:
            scanned += 1
            case_id = int(row["case_id"])
            header_fields = _coerce_header_fields(row.get("header_fields"))
            if not header_fields:
                continue
            docket_entries = _coerce_docket_entries(row.get("docket_entries"))

            judges = _extract_judge_display_list(header_fields)
            parties = (
                header_fields.get("parties")
                if isinstance(header_fields.get("parties"), list)
                else []
            )
            if case_entities is not None:
                try:
                    _refresh_case_entities(
                        conn,
                        case_entities,
                        case_id=case_id,
                        header_fields=header_fields,
                    )
                except Exception:
                    # Don't break the "make cards useful" button if this optional table
                    # is missing or has not been migrated yet.
                    pass
            party_count = header_fields.get("party_count")
            attorney_count = header_fields.get("attorney_count")
            if not isinstance(party_count, int) and parties:
                party_count = len(parties)
            if not isinstance(attorney_count, int) and parties:
                attorney_count = sum(
                    len(party.get("represented_by") or [])
                    for party in parties
                    if isinstance(party, dict)
                )
            entry_count = len(docket_entries)
            recent_entries = _extract_recent_docket_entries_for_preview(docket_entries, limit=5)

            if judges:
                _upsert_case_field(
                    conn,
                    pcl_case_fields,
                    case_id,
                    "docket_judges",
                    field_value_text=" | ".join(judges),
                    field_value_json=judges,
                    now=now,
                )
                updated_fields += 1

            if isinstance(party_count, int):
                _upsert_case_field(
                    conn,
                    pcl_case_fields,
                    case_id,
                    "docket_party_count",
                    field_value_text=str(party_count),
                    field_value_json=party_count,
                    now=now,
                )
                updated_fields += 1

            if isinstance(attorney_count, int):
                _upsert_case_field(
                    conn,
                    pcl_case_fields,
                    case_id,
                    "docket_attorney_count",
                    field_value_text=str(attorney_count),
                    field_value_json=attorney_count,
                    now=now,
                )
                updated_fields += 1

            if parties:
                attorneys = _extract_attorneys_from_parties(parties)
                summary = _flatten_parties_for_search(parties)
                party_names = _extract_party_names(parties, limit=250)
                attorney_names = _extract_attorney_names(attorneys, limit=250) if attorneys else []
                charge_items = _extract_charge_items_from_parties(parties, limit=40) if parties else []
                _upsert_case_field(
                    conn,
                    pcl_case_fields,
                    case_id,
                    "docket_parties",
                    field_value_text=None,
                    field_value_json=parties,
                    now=now,
                )
                updated_fields += 1
                _upsert_case_field(
                    conn,
                    pcl_case_fields,
                    case_id,
                    "docket_party_names",
                    field_value_text=" | ".join(party_names) if party_names else None,
                    field_value_json=party_names or None,
                    now=now,
                )
                updated_fields += 1
                _upsert_case_field(
                    conn,
                    pcl_case_fields,
                    case_id,
                    "docket_attorneys",
                    field_value_text=None,
                    field_value_json=attorneys or None,
                    now=now,
                )
                updated_fields += 1
                _upsert_case_field(
                    conn,
                    pcl_case_fields,
                    case_id,
                    "docket_party_summary",
                    field_value_text=summary or None,
                    field_value_json=None,
                    now=now,
                )
                updated_fields += 1
                _upsert_case_field(
                    conn,
                    pcl_case_fields,
                    case_id,
                    "docket_attorney_names",
                    field_value_text=" | ".join(attorney_names) if attorney_names else None,
                    field_value_json=attorney_names or None,
                    now=now,
                )
                updated_fields += 1
                _upsert_case_field(
                    conn,
                    pcl_case_fields,
                    case_id,
                    "docket_charges",
                    field_value_text=(
                        " | ".join(
                            f"{item.get('count')}{(' - ' + item.get('disposition')) if item.get('disposition') else ''}"
                            for item in charge_items
                            if isinstance(item, dict) and item.get("count")
                        )
                        if charge_items
                        else None
                    ),
                    field_value_json=charge_items or None,
                    now=now,
                )
                updated_fields += 1

            _upsert_case_field(
                conn,
                pcl_case_fields,
                case_id,
                "docket_entry_count",
                field_value_text=str(entry_count),
                field_value_json=entry_count,
                now=now,
            )
            updated_fields += 1
            _upsert_case_field(
                conn,
                pcl_case_fields,
                case_id,
                "docket_recent_entries",
                field_value_text=None,
                field_value_json=recent_entries or None,
                now=now,
            )
            updated_fields += 1

            existing_last = str(row.get("judge_last_name") or "").strip()
            if not existing_last and judges:
                last_name = _guess_last_name_from_judge_label(judges[0])
                if last_name:
                    conn.execute(
                        update(pcl_cases)
                        .where(pcl_cases.c.id == case_id)
                        .values(judge_last_name=last_name, updated_at=now)
                    )
                    updated_cases += 1

    return {
        "scanned": scanned,
        "updated_fields": updated_fields,
        "updated_cases": updated_cases,
    }


def _extract_attorneys_from_parties(parties: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    attorneys: List[Dict[str, Any]] = []
    for party in parties:
        if not isinstance(party, dict):
            continue
        party_name = party.get("name")
        party_type = party.get("party_type")
        for attorney in party.get("represented_by") or []:
            if not isinstance(attorney, dict):
                continue
            enriched = dict(attorney)
            if party_name:
                enriched["party_name"] = party_name
            if party_type:
                enriched["party_type"] = party_type
            attorneys.append(enriched)
    return attorneys


def _extract_attorney_names(attorneys: Any, *, limit: int = 25) -> List[str]:
    """Return a stable, unique list of counsel names for lightweight card UIs."""
    if not isinstance(attorneys, list) or limit <= 0:
        return []
    names: List[str] = []
    seen: set[str] = set()
    for item in attorneys:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        names.append(name)
        if len(names) >= limit:
            break
    return names


def _extract_party_names(parties: Any, *, limit: int = 25) -> List[str]:
    """Return a stable, unique list of party names for lightweight card UIs."""
    if not isinstance(parties, list) or limit <= 0:
        return []
    names: List[str] = []
    seen: set[str] = set()
    for item in parties:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        names.append(name)
        if len(names) >= limit:
            break
    return names


def _extract_charge_items_from_parties(
    parties: Any, *, limit: int = 40
) -> List[Dict[str, str]]:
    """Extract PACER 'Pending/Terminated Counts' and 'Complaints' rows.

    Each item carries the raw count label and disposition when present.
    """
    if not isinstance(parties, list) or limit <= 0:
        return []
    items: List[Dict[str, str]] = []
    for party in parties:
        if not isinstance(party, dict):
            continue
        for section in ("pending_counts", "terminated_counts", "complaints"):
            for row in party.get(section) or []:
                if not isinstance(row, dict):
                    continue
                count_text = str(row.get("count") or "").strip()
                disposition = str(row.get("disposition") or "").strip()
                if not count_text:
                    continue
                if count_text.strip().lower() == "none":
                    continue
                items.append(
                    {
                        "section": section,
                        "count": count_text,
                        "disposition": disposition,
                    }
                )
                if len(items) >= limit:
                    return items
    return items


def _extract_recent_docket_entries_for_preview(
    docket_entries: Any, *, limit: int = 5
) -> List[Dict[str, Any]]:
    """Normalize docket entry shapes into a small list for card previews."""
    if not isinstance(docket_entries, list) or limit <= 0:
        return []
    trimmed = docket_entries[-limit:]
    normalized: List[Dict[str, Any]] = []
    for entry in reversed(trimmed):
        if not isinstance(entry, dict):
            continue
        date_value = (
            entry.get("dateFiled")
            or entry.get("date_filed")
            or entry.get("filingDate")
            or entry.get("filing_date")
            or entry.get("date")
            or entry.get("docketTextDate")
            or entry.get("docket_text_date")
            or entry.get("docketDate")
            or entry.get("docket_date")
        )
        doc_value = (
            entry.get("documentNumber")
            or entry.get("document_number")
            or entry.get("docNumber")
            or entry.get("doc_number")
            or entry.get("doc_num")
            or entry.get("doc")
        )
        desc_value = (
            entry.get("description")
            or entry.get("docketText")
            or entry.get("docket_text")
            or entry.get("text")
            or entry.get("entry_text")
            or entry.get("docketEntryText")
        )

        date_filed = str(date_value or "").strip()
        doc_number = str(doc_value or "").strip()
        description = str(desc_value or "").strip()
        if not (date_filed or doc_number or description):
            continue
        normalized.append(
            {
                "dateFiled": date_filed or None,
                "documentNumber": doc_number or None,
                "description": description or None,
            }
        )
    return normalized


def _flatten_parties_for_search(parties: List[Dict[str, Any]]) -> str:
    parts: List[str] = []
    for party in parties:
        if not isinstance(party, dict):
            continue
        label = party.get("party_heading") or party.get("party_type")
        name = party.get("name")
        if label and name:
            parts.append(f"{label}: {name}")
        elif label:
            parts.append(str(label))
        elif name:
            parts.append(str(name))
        for attorney in party.get("represented_by") or []:
            if not isinstance(attorney, dict):
                continue
            attorney_name = attorney.get("name")
            if attorney_name:
                parts.append(str(attorney_name))
            for field_name in (
                "organization",
                "emails",
                "phones",
                "faxes",
                "websites",
                "designations",
                "roles",
            ):
                value = attorney.get(field_name)
                if isinstance(value, list):
                    for item in value:
                        if item:
                            parts.append(str(item))
                elif value:
                    parts.append(str(value))
        for field_name in (
            "highest_offense_level_opening",
            "highest_offense_level_terminated",
        ):
            value = party.get(field_name)
            if value:
                parts.append(str(value))
        for field_name in ("pending_counts", "terminated_counts", "complaints"):
            for item in party.get(field_name) or []:
                if not isinstance(item, dict):
                    continue
                if item.get("count"):
                    parts.append(str(item["count"]))
                if item.get("disposition"):
                    parts.append(str(item["disposition"]))
    return " | ".join(parts)


def _normalize_case_entity_value(value: Any) -> str:
    """Normalize values for case_entities searches/deduping.

    Keep this conservative: lower-case, collapse whitespace, replace
    punctuation with spaces so user searches match reliably.
    """
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    raw = re.sub(r"[^a-z0-9]+", " ", raw)
    return re.sub(r"\s+", " ", raw).strip()


def _merge_entity_meta(target: Dict[str, Any], incoming: Dict[str, Any]) -> None:
    """Merge meta JSON for duplicate entities (same normalized value)."""
    for key, value in (incoming or {}).items():
        if value is None or value == "" or value == []:
            continue
        existing = target.get(key)
        if existing is None:
            target[key] = value
            continue
        if isinstance(existing, list) and isinstance(value, list):
            _merge_unique_list(existing, [str(v) for v in value if str(v).strip()])
            continue
        if isinstance(existing, list) and not isinstance(value, list):
            _merge_unique_list(existing, [str(value)])
            continue
        if not isinstance(existing, list) and isinstance(value, list):
            merged: List[str] = []
            _merge_unique_list(merged, [str(existing)])
            _merge_unique_list(merged, [str(v) for v in value if str(v).strip()])
            target[key] = merged
            continue
        if existing == value:
            continue
        target[key] = [str(existing), str(value)]


def _build_case_entities_from_header_fields(
    header_fields: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Derive normalized case_entities rows from saved docket header fields.

    This is intentionally redundant with the nested `docket_header_fields` JSON:
    it gives us a stable, compact, searchable store for judges/parties/counsel/charges
    without relying on long, truncated summary text fields.
    """

    entities: Dict[tuple[str, str], Dict[str, Any]] = {}

    def _add(
        entity_type: str,
        value: Any,
        *,
        source_field: str = "docket_header_fields",
        meta_json: Optional[Dict[str, Any]] = None,
    ) -> None:
        text = str(value or "").strip()
        if not text:
            return
        norm = _normalize_case_entity_value(text)
        if not norm:
            return
        key = (entity_type, norm)
        existing = entities.get(key)
        if existing is None:
            entities[key] = {
                "entity_type": entity_type,
                "value": text,
                "value_normalized": norm,
                "source_field": source_field,
                "meta_json": meta_json or None,
            }
            return
        if meta_json:
            existing_meta = existing.get("meta_json") or {}
            if not isinstance(existing_meta, dict):
                existing_meta = {}
            _merge_entity_meta(existing_meta, meta_json)
            existing["meta_json"] = existing_meta or None

    # Judges
    for label in header_fields.get("judges") or []:
        _add("judge", label, meta_json={"role": "judge"})
    for label in header_fields.get("assigned_to") or []:
        _add("judge", label, meta_json={"role": "assigned_to"})
    for label in header_fields.get("referred_to") or []:
        _add("judge", label, meta_json={"role": "referred_to"})

    # Parties / Counsel / Charges
    parties = header_fields.get("parties")
    if not isinstance(parties, list):
        parties = []
    for party in parties:
        if not isinstance(party, dict):
            continue
        party_name = str(party.get("name") or "").strip()
        party_type = str(party.get("party_type") or "").strip()
        party_heading = str(party.get("party_heading") or "").strip()
        party_index = party.get("party_index")

        if party_name:
            _add(
                "party",
                party_name,
                meta_json={
                    "party_type": party_type or None,
                    "party_heading": party_heading or None,
                    "party_index": party_index if isinstance(party_index, int) else None,
                },
            )

        for attorney in party.get("represented_by") or []:
            if not isinstance(attorney, dict):
                continue
            name = str(attorney.get("name") or "").strip()
            if not name:
                continue
            meta = {
                "party_names": [party_name] if party_name else [],
                "party_types": [party_type] if party_type else [],
                "party_headings": [party_heading] if party_heading else [],
                "organizations": [str(attorney.get("organization") or "").strip()]
                if str(attorney.get("organization") or "").strip()
                else [],
                "roles": [str(v).strip() for v in (attorney.get("roles") or []) if str(v).strip()],
                "designations": [
                    str(v).strip()
                    for v in (attorney.get("designations") or [])
                    if str(v).strip()
                ],
                "emails": [
                    str(v).strip()
                    for v in (attorney.get("emails") or [])
                    if str(v).strip()
                ],
                "phones": [
                    str(v).strip()
                    for v in (attorney.get("phones") or [])
                    if str(v).strip()
                ],
                "faxes": [
                    str(v).strip()
                    for v in (attorney.get("faxes") or [])
                    if str(v).strip()
                ],
                "websites": [
                    str(v).strip()
                    for v in (attorney.get("websites") or [])
                    if str(v).strip()
                ],
            }
            # Drop empty arrays so meta stays compact.
            meta = {k: v for k, v in meta.items() if v}
            _add("counsel", name, meta_json=meta or None)

        for section in ("pending_counts", "terminated_counts", "complaints"):
            for row in party.get(section) or []:
                if not isinstance(row, dict):
                    continue
                count_text = str(row.get("count") or "").strip()
                disposition = str(row.get("disposition") or "").strip()
                if not count_text or count_text.lower() == "none":
                    continue
                value = f"{count_text} - {disposition}" if disposition else count_text
                _add(
                    "charge",
                    value,
                    meta_json={
                        "section": section,
                        "count": count_text,
                        "disposition": disposition or None,
                        "party_name": party_name or None,
                    },
                )

    return list(entities.values())


def _refresh_case_entities(
    conn: Any,
    case_entities: Optional[Table],
    *,
    case_id: int,
    header_fields: Optional[Dict[str, Any]],
) -> int:
    if case_entities is None or not header_fields:
        return 0
    derived = _build_case_entities_from_header_fields(header_fields)
    conn.execute(case_entities.delete().where(case_entities.c.case_id == case_id))
    if not derived:
        return 0
    rows = [{"case_id": case_id, **item} for item in derived]
    conn.execute(case_entities.insert(), rows)
    return len(rows)


def _format_pacer_error(message: str, fetch_result: DocketFetchResult) -> str:
    details = []
    if fetch_result.form_action:
        details.append(f"form_action={fetch_result.form_action}")
    if fetch_result.form_payload:
        keys = sorted(fetch_result.form_payload.keys())
        details.append(f"form_keys={','.join(keys[:12])}")
    if not details:
        return message
    return f"{message} ({' ; '.join(details)})"


def _with_form_details(
    fetch_result: DocketFetchResult, html_text: str
) -> DocketFetchResult:
    action, payload, _ = _select_docket_form(html_text)
    if not action and not payload:
        action, payload, _ = _select_any_form(html_text)
    if not action or not payload:
        return fetch_result
    resolved = _resolve_form_action(fetch_result.url, action)
    truncated = _truncate_map(payload, 200)
    return DocketFetchResult(
        url=fetch_result.url,
        status_code=fetch_result.status_code,
        content_type=fetch_result.content_type,
        body=fetch_result.body,
        form_action=resolved,
        form_payload=truncated,
        request_debug=fetch_result.request_debug,
    )


def _truncate_text(value: str, max_len: int) -> str:
    if not value:
        return ""
    if len(value) <= max_len:
        return value
    return f"{value[: max_len - 3]}..."


def _looks_like_docket_shell(text: str) -> bool:
    if not text:
        return False
    if _looks_like_docket_report(text):
        return False
    lowered = text.lower()
    return (
        "district court cm/ecf" in lowered
        and ("docket sheet" in lowered or "docket report" in lowered)
        and ("case_number_text_area" in lowered or "output_format" in lowered)
    ) or _looks_like_case_query_page(lowered)


def _looks_like_case_query_page(lowered_text: str) -> bool:
    if not lowered_text:
        return False
    return (
        "cmecfmaincontent" in lowered_text
        and (
            "selection criteria for query" in lowered_text
            or "/cgi-bin/dktrpt.pl" in lowered_text
            or "docket report" in lowered_text
        )
    )


def _looks_like_docket_report(text: str) -> bool:
    if not text:
        return False
    lowered = text.lower()
    if (
        "docket text" in lowered
        and ("docket for case" in lowered or "criminal docket for case" in lowered or "civil docket for case" in lowered)
    ):
        return True
    if "docket text" in lowered and "filing date" in lowered:
        return True
    if "docket text" in lowered and "u.s. bankruptcy court" in lowered:
        return True
    return False


def _submit_docket_form(
    http_client: Any,
    html: str,
    base_url: str,
    case_number_full: Optional[str] = None,
    case_number: Optional[str] = None,
    case_office: Optional[str] = None,
    case_year: Optional[str] = None,
    case_type: Optional[str] = None,
    preferred_output_format: Optional[str] = None,
) -> Optional[DocketFetchResult]:
    action, payload, form_html = _select_docket_form(html)
    if not action or not payload:
        return None
    enctype = _extract_form_enctype(form_html or html)
    case_id = _extract_case_id_from_url(base_url)
    if case_id:
        payload.setdefault("case_id", case_id)
        payload.setdefault("all_case_ids", case_id)
    formatted_case_number = _format_case_number_for_pacer(
        case_office=case_office,
        case_year=case_year,
        case_type=case_type,
        case_number=case_number,
        case_number_full=case_number_full,
    )
    if case_number_full:
        payload.setdefault("case_number_full", case_number_full)
        payload.setdefault("case_number", case_number_full)
        payload.setdefault("case_num", case_number_full)
        payload["case_number_text_area_0"] = case_number_full
    if formatted_case_number:
        payload["case_num"] = formatted_case_number
        payload["case_number_text_area_0"] = formatted_case_number
    if case_number and "case_number_text_area_0" not in payload:
        payload["case_number_text_area_0"] = case_number
    if case_id:
        payload["all_case_ids"] = case_id
        payload.setdefault("case_id", case_id)
        if "case_number_text_area_0" not in payload:
            payload["case_number_text_area_0"] = case_id
    payload.setdefault("date_range_type", "Filed")
    payload.setdefault("date_from", "")
    payload.setdefault("date_to", "")
    payload.setdefault("documents_numbered_from_", "")
    payload.setdefault("documents_numbered_to_", "")
    payload.setdefault("report_type", "docket")
    payload.setdefault("sort1", "oldest date first")
    payload.setdefault("sort2", "")

    output_format = payload.get("output_format", "")
    if output_format:
        output_format = output_format.lower()
    preferred_output = (preferred_output_format or "").strip().lower()
    if preferred_output in {"xml", "html", "pdf"}:
        output_format = preferred_output
    elif output_format not in {"xml", "html", "pdf"}:
        output_format = "xml" if _form_supports_xml(form_html or html) else "html"

    def _submit_with_format(
        fmt: str,
        *,
        case_value: Optional[str],
        all_case_ids: Optional[str],
    ) -> DocketFetchResult:
        local_payload = dict(payload)
        if case_value:
            local_payload["case_number_text_area_0"] = case_value
        if all_case_ids is not None:
            local_payload["all_case_ids"] = all_case_ids
        if fmt == "xml":
            local_payload["output_format"] = "XML"
            local_payload["outputXML_TXT"] = "XML"
            local_payload["output_format_type"] = "XML"
            local_payload["format"] = "XML"
        elif fmt == "html":
            local_payload["output_format"] = "html"
            local_payload["outputXML_TXT"] = "HTML"
            local_payload["output_format_type"] = "html"
            local_payload["format"] = "html"
            local_payload["output"] = "html"
        local_payload.setdefault("report_type", "docket")
        action_url = _resolve_form_action(base_url, action)
        if case_id and "case_id=" not in action_url:
            separator = "&" if "?" in action_url else "?"
            action_url = f"{action_url}{separator}case_id={case_id}"
        if enctype and "multipart/form-data" in enctype.lower():
            boundary = _make_multipart_boundary()
            encoded = _encode_multipart_form(local_payload, boundary)
            content_type = f"multipart/form-data; boundary={boundary}"
        else:
            encoded = urlencode(local_payload).encode("utf-8")
            content_type = "application/x-www-form-urlencoded"
        response = _request_with_login_retry(
            http_client,
            "POST",
            action_url,
            headers={
                "Content-Type": content_type,
                "Referer": base_url,
                "Accept": "application/xml, text/html",
            },
            data=encoded,
            include_cookie=True,
        )
        request_debug = _build_request_debug(
            http_client,
            url=action_url,
            method="POST",
            content_type=content_type,
            payload=local_payload,
            note="docket_form_submit",
        )
        followup = _submit_confirm_form(
            http_client,
            response,
            referer=action_url,
            desired_output=fmt,
        )
        if followup is not None:
            followup.form_payload = local_payload
            followup.request_debug = request_debug
            return followup
        content_type = response.headers.get("Content-Type", "")
        return DocketFetchResult(
            url=action_url,
            status_code=response.status_code,
            content_type=content_type,
            body=response.body,
            form_action=action_url,
            form_payload=local_payload,
            request_debug=request_debug,
        )

    case_values = [
        formatted_case_number or case_number_full or case_number,
        case_number_full,
        case_number,
    ]
    case_values = [value for value in case_values if value]
    case_values = list(dict.fromkeys(case_values))
    all_case_options = [case_id, "", None]
    result = None
    for case_value in case_values:
        for all_case_ids in all_case_options:
            result = _submit_with_format(output_format, case_value=case_value, all_case_ids=all_case_ids)
            if not _looks_like_docket_shell(result.body.decode("utf-8", errors="replace")):
                return result
    if output_format == "xml" and result is not None:
        if _looks_like_docket_shell(result.body.decode("utf-8", errors="replace")):
            result = _submit_with_format("html", case_value=case_values[0] if case_values else None, all_case_ids=case_id)
    return result


def _resolve_form_action(base_url: str, action: str) -> str:
    if not action:
        return base_url
    return urljoin(base_url, action)


def _select_docket_form(html: str) -> tuple[Optional[str], Dict[str, str], str]:
    forms = []
    for match in re.finditer(r"<form\\b[^>]*>.*?</form>", html, re.IGNORECASE | re.DOTALL):
        form_html = match.group(0)
        tag_match = re.search(r"<form([^>]*)>", form_html, re.IGNORECASE)
        attrs = tag_match.group(1) if tag_match else ""
        action = _extract_attr(attrs, "action")
        score = 0
        if action and "dktrpt" in action.lower():
            score += 3
        if "case_number_text_area" in form_html.lower():
            score += 2
        if "docket report" in form_html.lower() or "docket sheet" in form_html.lower():
            score += 1
        forms.append((score, action, form_html))
    if not forms:
        return None, {}, ""
    forms.sort(key=lambda item: item[0], reverse=True)
    _, action, form_html = forms[0]
    payload = _extract_form_fields(form_html)
    return action, payload, form_html


def _select_any_form(html: str) -> tuple[Optional[str], Dict[str, str], str]:
    for match in re.finditer(r"<form\\b[^>]*>.*?</form>", html, re.IGNORECASE | re.DOTALL):
        form_html = match.group(0)
        tag_match = re.search(r"<form([^>]*)>", form_html, re.IGNORECASE)
        attrs = tag_match.group(1) if tag_match else ""
        action = _extract_attr(attrs, "action")
        payload = _extract_form_fields(form_html)
        if payload:
            return action, payload, form_html
    return None, {}, ""


def _extract_form_enctype(form_html: str) -> Optional[str]:
    if not form_html:
        return None
    tag_match = re.search(r"<form([^>]*)>", form_html, re.IGNORECASE)
    attrs = tag_match.group(1) if tag_match else ""
    enctype = _extract_attr(attrs, "enctype") or _extract_attr(attrs, "ENCtype")
    if enctype:
        return enctype
    return None


def _submit_docket_report_direct(
    http_client: Any,
    case_link: str,
    *,
    case_id: Optional[str],
    output_format: str = "html",
    all_case_ids: Optional[str] = None,
    case_num: Optional[str] = None,
) -> Optional[DocketFetchResult]:
    if not case_link or not case_id:
        return None
    parsed = urlparse(case_link)
    if not parsed.scheme or not parsed.netloc:
        return None
    action_url = f"{parsed.scheme}://{parsed.netloc}/cgi-bin/DktRpt.pl?1-L_1_0-1"
    if all_case_ids is None:
        all_case_ids = case_id
    if case_num is None:
        case_num = " "
    payload = {
        "all_case_ids": all_case_ids,
        "sort1": "oldest date first",
        "date_range_type": "Filed",
        "output_format": output_format,
        "case_num": case_num,
        "date_from": "1/1/1960",
        "date_to": "",
        "documents_numbered_from_": "",
        "documents_numbered_to_": "",
        "list_of_parties_and_counsel": "on",
        "terminated_parties": "on",
        "pdf_header": "1",
    }
    boundary = _make_multipart_boundary()
    encoded = _encode_multipart_form(payload, boundary)
    content_type = f"multipart/form-data; boundary={boundary}"
    response = _request_with_login_retry(
        http_client,
        "POST",
        action_url,
        headers={
            "Content-Type": content_type,
            "Referer": case_link,
            "Accept": "application/xml, text/html",
        },
        data=encoded,
        include_cookie=True,
    )
    request_debug = _build_request_debug(
        http_client,
        url=action_url,
        method="POST",
        content_type=content_type,
        payload=payload,
        note="docket_direct_submit",
    )
    return DocketFetchResult(
        url=action_url,
        status_code=response.status_code,
        content_type=response.headers.get("Content-Type", ""),
        body=response.body,
        form_action=action_url,
        form_payload=payload,
        request_debug=request_debug,
    )


def _make_multipart_boundary() -> str:
    seed = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
    return f"----PacerBoundary{seed}"


def _encode_multipart_form(fields: Dict[str, Any], boundary: str) -> bytes:
    lines: List[str] = []
    for name, value in fields.items():
        if value is None:
            value = ""
        lines.append(f"--{boundary}")
        lines.append(f'Content-Disposition: form-data; name="{name}"')
        lines.append("")
        lines.append(str(value))
    lines.append(f"--{boundary}--")
    lines.append("")
    return "\r\n".join(lines).encode("utf-8")


def _submit_confirm_form(
    http_client: Any,
    response: Any,
    *,
    referer: str,
    desired_output: str = "xml",
) -> Optional[DocketFetchResult]:
    content_type = response.headers.get("Content-Type", "")
    if "html" not in content_type.lower():
        return None
    body = response.body.decode("utf-8", errors="replace")
    if not _looks_like_docket_shell(body) and "confirm" not in body.lower():
        return None
    action, payload = _select_confirm_form(body, desired_output=desired_output)
    if not action or not payload:
        return None
    action_url = _resolve_form_action(referer, action)
    encoded = urlencode(payload).encode("utf-8")
    follow = _request_with_login_retry(
        http_client,
        "POST",
        action_url,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": referer,
            "Accept": "application/xml, text/html",
        },
        data=encoded,
        include_cookie=True,
    )
    return DocketFetchResult(
        url=action_url,
        status_code=follow.status_code,
        content_type=follow.headers.get("Content-Type", ""),
        body=follow.body,
        form_action=action_url,
        form_payload=payload,
    )


def _select_confirm_form(html: str, *, desired_output: str = "xml") -> tuple[Optional[str], Dict[str, str]]:
    forms = []
    for match in re.finditer(r"<form\\b[^>]*>.*?</form>", html, re.IGNORECASE | re.DOTALL):
        form_html = match.group(0)
        tag_match = re.search(r"<form([^>]*)>", form_html, re.IGNORECASE)
        attrs = tag_match.group(1) if tag_match else ""
        action = _extract_attr(attrs, "action")
        score = 0
        if re.search(r"confirm", form_html, re.IGNORECASE):
            score += 3
        if "outputXML_TXT" in form_html:
            score += 2
        if "view report" in form_html.lower():
            score += 1
        forms.append((score, action, form_html))
    if not forms:
        return None, {}
    forms.sort(key=lambda item: item[0], reverse=True)
    _, action, form_html = forms[0]
    payload = _extract_form_fields(form_html)
    if "confirmCharge" in payload:
        payload["confirmCharge"] = "Y"
    if "confirmCharges" in payload:
        payload["confirmCharges"] = "Y"
    if desired_output.lower() == "html":
        if "outputXML_TXT" in payload:
            payload["outputXML_TXT"] = "HTML"
        if "output_format" in payload:
            payload["output_format"] = "html"
        if "output_format_type" in payload:
            payload["output_format_type"] = "html"
        if "format" in payload:
            payload["format"] = "html"
    else:
        if "outputXML_TXT" in payload:
            payload["outputXML_TXT"] = "XML"
        if "output_format" in payload:
            payload["output_format"] = "XML"
        if "output_format_type" in payload:
            payload["output_format_type"] = "XML"
        if "format" in payload:
            payload["format"] = "XML"
    return action, payload


def _fetch_docket_report_multistep(
    http_client: Any,
    case_link: str,
    *,
    case_number_full: Optional[str],
    case_office: Optional[str] = None,
    case_year: Optional[str] = None,
    case_type: Optional[str] = None,
    case_number: Optional[str] = None,
    output_format: str = "xml",
) -> Optional[DocketFetchResult]:
    if not case_number_full:
        return None
    parsed = urlparse(case_link or "")
    if not parsed.scheme or not parsed.netloc:
        return None
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    search_url = f"{base_url}/n/beam/servlet/TransportRoom?servlet=CaseSearch.jsp"
    search_response = _request_with_login_retry(
        http_client,
        "GET",
        search_url,
        headers={"Accept": "text/html"},
        include_cookie=True,
    )
    if search_response.status_code != 200:
        return None
    search_html = search_response.body.decode("utf-8", errors="replace")
    search_form = _find_first_form(search_html)
    if not search_form:
        return None
    search_action, search_payload = search_form
    search_payload.setdefault("servlet", "CaseSelectionTable.jsp")
    formatted_case_number = _format_case_number_for_pacer(
        case_office=case_office,
        case_year=case_year,
        case_type=case_type,
        case_number=case_number,
        case_number_full=case_number_full,
    )
    search_payload.setdefault("csnum1", formatted_case_number or case_number_full)
    search_payload.setdefault("csnum2", "")
    search_payload.setdefault("aName", "")
    search_payload.setdefault("searchPty", "pty")
    search_action_url = _resolve_form_action(search_url, search_action)
    search_submit = _request_with_login_retry(
        http_client,
        "POST",
        search_action_url,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": search_url,
            "Accept": "text/html",
        },
        data=urlencode(search_payload).encode("utf-8"),
        include_cookie=True,
    )
    if search_submit.status_code != 200:
        return None
    summary_link = _extract_case_summary_link(
        search_submit.body.decode("utf-8", errors="replace")
    )
    if not summary_link:
        return None
    summary_url = _resolve_form_action(search_action_url, summary_link)
    summary_response = _request_with_login_retry(
        http_client,
        "GET",
        summary_url,
        headers={"Accept": "text/html"},
        include_cookie=True,
    )
    if summary_response.status_code != 200:
        return None
    summary_html = summary_response.body.decode("utf-8", errors="replace")
    full_docket_form = _find_form_with_input(summary_html, "fullDocket")
    if not full_docket_form:
        return None
    docket_action, docket_payload = full_docket_form
    docket_action_url = _resolve_form_action(summary_url, docket_action)
    docket_submit = _request_with_login_retry(
        http_client,
        "POST",
        docket_action_url,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": summary_url,
            "Accept": "text/html",
        },
        data=urlencode(docket_payload).encode("utf-8"),
        include_cookie=True,
    )
    if docket_submit.status_code != 200:
        return None
    filter_form = _find_first_form(
        docket_submit.body.decode("utf-8", errors="replace")
    )
    if not filter_form:
        return None
    filter_action, filter_payload = filter_form
    if output_format == "html":
        filter_payload["outputXML_TXT"] = "HTML"
        filter_payload["output_format"] = "html"
        filter_payload["output_format_type"] = "html"
        filter_payload["format"] = "html"
    else:
        filter_payload["outputXML_TXT"] = "XML"
        filter_payload["output_format"] = "XML"
        filter_payload["output_format_type"] = "XML"
        filter_payload["format"] = "XML"
    filter_action_url = _resolve_form_action(docket_action_url, filter_action)
    filter_response = _request_with_login_retry(
        http_client,
        "POST",
        filter_action_url,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": docket_action_url,
            "Accept": "text/html, application/xml",
        },
        data=urlencode(filter_payload).encode("utf-8"),
        include_cookie=True,
    )
    if filter_response.status_code != 200:
        return None
    confirm = _submit_confirm_form(
        http_client,
        filter_response,
        referer=filter_action_url,
        desired_output=output_format,
    )
    if confirm is not None:
        return confirm
    return DocketFetchResult(
        url=filter_action_url,
        status_code=filter_response.status_code,
        content_type=filter_response.headers.get("Content-Type", ""),
        body=filter_response.body,
        form_action=filter_action_url,
        form_payload=filter_payload,
    )


def _find_first_form(html_text: str) -> Optional[tuple[str, Dict[str, str]]]:
    match = re.search(r"<form\\b[^>]*>.*?</form>", html_text, re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    form_html = match.group(0)
    tag_match = re.search(r"<form([^>]*)>", form_html, re.IGNORECASE)
    attrs = tag_match.group(1) if tag_match else ""
    action = _extract_attr(attrs, "action") or ""
    payload = _extract_form_fields(form_html)
    return action, payload


def _find_form_with_input(html_text: str, input_name: str) -> Optional[tuple[str, Dict[str, str]]]:
    for match in re.finditer(r"<form\\b[^>]*>.*?</form>", html_text, re.IGNORECASE | re.DOTALL):
        form_html = match.group(0)
        if input_name not in form_html:
            continue
        tag_match = re.search(r"<form([^>]*)>", form_html, re.IGNORECASE)
        attrs = tag_match.group(1) if tag_match else ""
        action = _extract_attr(attrs, "action") or ""
        payload = _extract_form_fields(form_html)
        return action, payload
    return None


def _extract_case_summary_link(html_text: str) -> Optional[str]:
    match = re.search(r"href=[\"']([^\"']*CaseSummary[^\"']*)[\"']", html_text)
    if match:
        return match.group(1)
    match = re.search(r"href=[\"']([^\"']*CaseSummary.*?)[\"']", html_text)
    return match.group(1) if match else None


def _looks_like_login_redirect(html_text: str) -> bool:
    if not html_text:
        return False
    lowered = html_text.lower()
    return (
        "pacer.login.uscourts.gov" in lowered
        or "csologin" in lowered
        or "login.jsf" in lowered
    )


def _request_with_login_retry(
    http_client: Any,
    method: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    data: Optional[bytes] = None,
    include_cookie: bool = False,
    _retried: bool = False,
) -> Any:
    response = http_client.request(
        method,
        url,
        headers=headers,
        data=data,
        include_cookie=include_cookie,
    )
    content_type = response.headers.get("Content-Type", "")
    if (
        not _retried
        and "html" in content_type.lower()
        and _looks_like_login_redirect(response.body.decode("utf-8", errors="replace"))
    ):
        refresh = getattr(http_client, "refresh_token", None)
        if callable(refresh):
            refresh()
            return _request_with_login_retry(
                http_client,
                method,
                url,
                headers=headers,
                data=data,
                include_cookie=include_cookie,
                _retried=True,
            )
    return response


def _format_case_number_for_pacer(
    *,
    case_office: Optional[str],
    case_year: Optional[str],
    case_type: Optional[str],
    case_number: Optional[str],
    case_number_full: Optional[str],
) -> Optional[str]:
    if case_office and case_year and case_type and case_number:
        year = str(case_year)[-2:]
        try:
            num = int(case_number)
            number_part = f"{num:05d}"
        except (ValueError, TypeError):
            number_part = str(case_number)
        return f"{case_office}:{year}-{case_type}-{number_part}"
    return case_number_full


def _extract_form_fields(html: str) -> Dict[str, str]:
    fields: Dict[str, str] = {}
    for match in re.finditer(r"<input([^>]+)>", html, re.IGNORECASE):
        attrs = match.group(1)
        name = _extract_attr(attrs, "name")
        if not name:
            continue
        input_type = (_extract_attr(attrs, "type") or "text").lower()
        value = _extract_attr(attrs, "value") or ""
        checked = "checked" in attrs.lower()
        if input_type in {"checkbox", "radio"} and not checked:
            continue
        fields[name] = value

    for match in re.finditer(r"<select([^>]+)>(.*?)</select>", html, re.IGNORECASE | re.DOTALL):
        attrs, body = match.groups()
        name = _extract_attr(attrs, "name")
        if not name:
            continue
        selected = re.search(r"<option[^>]*selected[^>]*value=[\"']([^\"']*)[\"']", body, re.IGNORECASE)
        if selected:
            fields[name] = selected.group(1)
            continue
        fallback = re.search(r"<option[^>]*value=[\"']([^\"']*)[\"']", body, re.IGNORECASE)
        if fallback:
            fields[name] = fallback.group(1)
    for match in re.finditer(r"<textarea([^>]*)>(.*?)</textarea>", html, re.IGNORECASE | re.DOTALL):
        attrs, body = match.groups()
        name = _extract_attr(attrs, "name")
        if not name:
            continue
        fields[name] = html.unescape(body.strip())
    if "output_format" not in fields:
        xml_option = re.search(
            r"name=[\"']output_format[\"'][^>]*value=[\"'](xml|XML)[\"']",
            html,
        )
        if xml_option:
            fields["output_format"] = xml_option.group(1)
    return fields


def _truncate_map(values: Dict[str, str], max_len: int) -> Dict[str, str]:
    trimmed = {}
    for key, value in values.items():
        if value is None:
            trimmed[key] = ""
            continue
        string_value = str(value)
        trimmed[key] = _truncate_text(string_value, max_len)
    return trimmed


def _extract_int_header(headers: Dict[str, Any], names: List[str]) -> Optional[int]:
    if not headers:
        return None
    lowered = {str(key).lower(): value for key, value in headers.items()}
    for name in names:
        raw = lowered.get(name.lower())
        if raw is None:
            continue
        text = str(raw).strip()
        if not text:
            continue
        match = re.search(r"-?\d+", text.replace(",", ""))
        if not match:
            continue
        try:
            return int(match.group(0))
        except ValueError:
            continue
    return None


def _build_request_debug(
    http_client: Any,
    *,
    url: str,
    method: str,
    content_type: str,
    payload: Dict[str, Any],
    note: str,
) -> Dict[str, Any]:
    cookie_names: List[str] = []
    getter = getattr(http_client, "get_cookie_names", None)
    if callable(getter):
        try:
            cookie_names = list(getter())
        except Exception:
            cookie_names = []
    safe_fields = {
        "all_case_ids",
        "case_num",
        "case_number_text_area_0",
        "output_format",
        "outputXML_TXT",
        "date_from",
        "date_to",
        "documents_numbered_from_",
        "documents_numbered_to_",
        "sort1",
        "report_type",
        "list_of_parties_and_counsel",
        "terminated_parties",
        "pdf_header",
    }
    payload_preview: Dict[str, Any] = {}
    for key in safe_fields:
        if key in payload:
            payload_preview[key] = payload.get(key)
    return {
        "note": note,
        "method": method,
        "url": url,
        "content_type": content_type,
        "payload_keys": sorted(list(payload.keys())),
        "payload_preview": payload_preview,
        "cookie_names": cookie_names,
    }


def _extract_attr(attrs: str, name: str) -> Optional[str]:
    match = re.search(rf"{name}\\s*=\\s*[\"']([^\"']*)[\"']", attrs, re.IGNORECASE)
    return match.group(1) if match else None


def _form_supports_xml(html: str) -> bool:
    return re.search(
        r"name=[\"']output_format[\"'][^>]*value=[\"']xml[\"']",
        html,
        re.IGNORECASE,
    ) is not None or re.search(
        r"name=[\"']outputXML_TXT[\"'][^>]*value=[\"']XML[\"']",
        html,
        re.IGNORECASE,
    ) is not None


def _force_docket_report(
    http_client: Any,
    case_link: str,
    *,
    case_number_full: Optional[str] = None,
) -> Optional[DocketFetchResult]:
    def _request_with_output(fmt: str) -> Optional[DocketFetchResult]:
        try:
            url = _build_docket_report_url(
                case_link,
                case_number_full=case_number_full,
                case_number=None,
                output_format=fmt,
                url_template=None,
            )
        except ValueError:
            return None
        response = _request_with_login_retry(
            http_client,
            "GET",
            url,
            headers={"Accept": "application/xml, text/html"},
            include_cookie=True,
        )
        return DocketFetchResult(
            url=url,
            status_code=response.status_code,
            content_type=response.headers.get("Content-Type", ""),
            body=response.body,
        )

    result = _request_with_output("XML")
    if result and _looks_like_docket_shell(
        result.body.decode("utf-8", errors="replace")
    ):
        return _request_with_output("HTML")
    return result


def _upsert_case_field(
    conn: Any,
    pcl_case_fields: Table,
    case_id: int,
    field_name: str,
    *,
    field_value_text: Optional[str],
    field_value_json: Optional[Any],
    now: datetime,
) -> None:
    if isinstance(field_value_text, str) and len(field_value_text) > 2000:
        field_value_text = f"{field_value_text[:1997]}..."
    existing = (
        conn.execute(
            select(pcl_case_fields.c.id).where(
                (pcl_case_fields.c.case_id == case_id)
                & (pcl_case_fields.c.field_name == field_name)
            )
        )
        .mappings()
        .first()
    )
    payload = {
        "field_value_text": field_value_text,
        "field_value_json": field_value_json,
        "updated_at": now,
    }
    if existing:
        conn.execute(
            update(pcl_case_fields)
            .where(pcl_case_fields.c.id == existing["id"])
            .values(**payload)
        )
        return
    conn.execute(
        pcl_case_fields.insert().values(
            case_id=case_id,
            field_name=field_name,
            field_value_text=field_value_text,
            field_value_json=field_value_json,
            created_at=now,
            updated_at=now,
        )
    )
