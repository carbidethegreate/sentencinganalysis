from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
import re
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlencode, urlparse
from xml.etree import ElementTree

from sqlalchemy import Table, select, update


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
        docket_output: str = "xml",
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
        )
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
        url = _build_docket_report_url(
            case_row["case_link"],
            case_number_full=case_row.get("case_number_full"),
            case_number=case_row.get("case_number"),
            output_format=self._docket_output,
            url_template=self._docket_url_template,
        )
        response = self._http_client.request(
            "GET",
            url,
            headers={"Accept": "application/xml, text/html"},
            include_cookie=True,
        )
        content_type = response.headers.get("Content-Type", "")
        return DocketFetchResult(
            url=url,
            status_code=response.status_code,
            content_type=content_type,
            body=response.body,
        )

    def _store_docket_payload(
        self,
        job: Dict[str, Any],
        case_row: Dict[str, Any],
        fetch_result: DocketFetchResult,
        docket_text: str,
        docket_entries: List[Dict[str, Any]],
        parsed_format: str,
    ) -> None:
        pcl_case_fields = self._tables.get("pcl_case_fields")
        receipt_table = self._tables.get("docket_enrichment_receipts")
        now = self._now()

        with self._engine.begin() as conn:
            if pcl_case_fields is not None:
                if docket_text:
                    _upsert_case_field(
                        conn,
                        pcl_case_fields,
                        case_row["id"],
                        "docket_text",
                        field_value_text=docket_text,
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
                conn.execute(
                    receipt_table.insert().values(
                        job_id=job["id"],
                        receipt_json=json.dumps(receipt_payload),
                        billable_pages=None,
                        fee=None,
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


def _extract_docket_payload(
    body: bytes,
    content_type: str,
) -> tuple[str, List[Dict[str, Any]], str]:
    text = body.decode("utf-8", errors="replace")
    if "xml" in (content_type or "").lower() or text.lstrip().startswith("<"):
        try:
            return _extract_docket_xml(text), _extract_docket_entries(text), "xml"
        except ElementTree.ParseError:
            return _strip_html(text), [], "html"
    return _strip_html(text), [], "html"


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
    cleaned = re.sub(r"<[^>]+>", " ", raw)
    cleaned = re.sub(r"\\s+", " ", cleaned)
    return cleaned.strip()


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
