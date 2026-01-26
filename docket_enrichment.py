from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import html
import json
import re
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlencode, urlparse
from xml.etree import ElementTree

from lxml import html as lxml_html
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
    form_action: Optional[str] = None
    form_payload: Optional[Dict[str, str]] = None


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
        )
        raw_html = None
        if parsed_format == "html":
            raw_html = fetch_result.body.decode("utf-8", errors="replace")
        if raw_html and _looks_like_docket_shell(raw_html):
            self._store_docket_payload(
                job,
                case_row,
                fetch_result,
                docket_text,
                docket_entries,
                parsed_format,
                raw_html=raw_html,
            )
            self._mark_failed(
                job,
                "PACER returned a docket form instead of the docket report.",
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
                    )
                    if multistep:
                        return multistep
                return submit
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
        *,
        raw_html: Optional[str] = None,
    ) -> None:
        pcl_case_fields = self._tables.get("pcl_case_fields")
        receipt_table = self._tables.get("docket_enrichment_receipts")
        now = self._now()
        docket_text_preview = _truncate_text(docket_text, 1000) if docket_text else ""
        html_body = raw_html
        if not html_body and parsed_format == "html":
            html_body = fetch_result.body.decode("utf-8", errors="replace")
        docket_is_shell = parsed_format == "html" and _looks_like_docket_shell(html_body or "")

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
                elif docket_text:
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
                if fetch_result.form_action:
                    receipt_payload["form_action"] = fetch_result.form_action
                if fetch_result.form_payload:
                    receipt_payload["form_payload"] = _truncate_map(
                        fetch_result.form_payload, 200
                    )
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
) -> tuple[str, List[Dict[str, Any]], str]:
    text = body.decode("utf-8", errors="replace")
    if "xml" in (content_type or "").lower() or text.lstrip().startswith("<"):
        try:
            return _extract_docket_xml(text), _extract_docket_entries(text), "xml"
        except ElementTree.ParseError:
            entries = _extract_docket_entries_from_html(text)
            return _extract_docket_text_from_entries(entries, text), entries, "html"
    entries = _extract_docket_entries_from_html(text)
    return _extract_docket_text_from_entries(entries, text), entries, "html"


def _extract_docket_entries_from_html(html_text: str) -> List[Dict[str, Any]]:
    try:
        tree = lxml_html.fromstring(html_text)
    except (ValueError, TypeError):
        return []

    rows = tree.xpath(
        "//table[.//text()[contains(., 'Docket Text')]]/tbody/tr"
    )
    if not rows:
        rows = tree.xpath(
            "//table[preceding-sibling::table[.//text()[contains(., 'Docket Text')]]]"
            "/tbody/tr"
        )

    entries: List[Dict[str, Any]] = []
    for row in rows[1:]:
        cells = row.xpath("./td")
        if len(cells) < 3:
            continue
        date_filed = _normalize_html_text(cells[0])
        if not date_filed:
            continue
        doc_number = _normalize_html_text(cells[1])
        description = _normalize_html_text(cells[2])
        entry = {"dateFiled": date_filed, "description": description}
        if doc_number:
            entry["documentNumber"] = doc_number
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
    cleaned = re.sub(r"<[^>]+>", " ", raw)
    cleaned = re.sub(r"\\s+", " ", cleaned)
    return cleaned.strip()


def _truncate_text(value: str, max_len: int) -> str:
    if not value:
        return ""
    if len(value) <= max_len:
        return value
    return f"{value[: max_len - 3]}..."


def _looks_like_docket_shell(text: str) -> bool:
    if not text:
        return False
    lowered = text.lower()
    return (
        "district court cm/ecf" in lowered
        and ("docket sheet" in lowered or "docket report" in lowered)
        and ("case_number_text_area" in lowered or "output_format" in lowered)
    )


def _submit_docket_form(
    http_client: Any,
    html: str,
    base_url: str,
    case_number_full: Optional[str] = None,
    case_number: Optional[str] = None,
) -> Optional[DocketFetchResult]:
    action, payload, form_html = _select_docket_form(html)
    if not action or not payload:
        return None
    case_id = _extract_case_id_from_url(base_url)
    if case_id:
        payload.setdefault("case_id", case_id)
        payload.setdefault("all_case_ids", case_id)
    if case_number_full:
        payload.setdefault("case_number_full", case_number_full)
        payload.setdefault("case_number", case_number_full)
        payload.setdefault("case_number_text_area_0", case_number_full)
    if case_number_full or case_number:
        payload["case_num"] = case_number_full or case_number
    if case_id and "case_number_text_area_0" not in payload:
        payload["case_number_text_area_0"] = case_id
    payload.setdefault("date_range_type", "Filed")
    payload.setdefault("date_from", "1/1/1960")
    payload.setdefault("date_to", "")
    payload.setdefault("report_type", "docket")
    payload.setdefault("sort1", "docnum")
    payload.setdefault("sort2", "filingdate")

    output_format = payload.get("output_format", "")
    if output_format:
        output_format = output_format.lower()
    if output_format not in {"xml", "html", "pdf"}:
        output_format = "xml" if _form_supports_xml(form_html or html) else "html"
        payload["output_format"] = "XML" if output_format == "xml" else output_format
    elif output_format == "xml":
        payload["output_format"] = "XML"

    payload.setdefault("output_format_type", payload.get("output_format"))
    payload.setdefault("report_type", "docket")
    payload.setdefault("format", payload.get("output_format"))
    action_url = _resolve_form_action(base_url, action)
    encoded = urlencode(payload).encode("utf-8")
    response = _request_with_login_retry(
        http_client,
        "POST",
        action_url,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": base_url,
            "Accept": "application/xml, text/html",
        },
        data=encoded,
        include_cookie=True,
    )
    followup = _submit_confirm_form(http_client, response, referer=action_url)
    if followup is not None:
        return followup
    content_type = response.headers.get("Content-Type", "")
    return DocketFetchResult(
        url=action_url,
        status_code=response.status_code,
        content_type=content_type,
        body=response.body,
        form_action=action_url,
        form_payload=payload,
    )


def _resolve_form_action(base_url: str, action: str) -> str:
    if action.startswith("http://") or action.startswith("https://"):
        return action
    parsed = urlparse(base_url)
    scheme = parsed.scheme or "https"
    host = parsed.netloc
    if action.startswith("/"):
        return f"{scheme}://{host}{action}"
    base_path = parsed.path.rsplit("/", 1)[0]
    return f"{scheme}://{host}{base_path}/{action}"


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


def _submit_confirm_form(
    http_client: Any,
    response: Any,
    *,
    referer: str,
) -> Optional[DocketFetchResult]:
    content_type = response.headers.get("Content-Type", "")
    if "html" not in content_type.lower():
        return None
    body = response.body.decode("utf-8", errors="replace")
    if not _looks_like_docket_shell(body) and "confirm" not in body.lower():
        return None
    action, payload = _select_confirm_form(body)
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


def _select_confirm_form(html: str) -> tuple[Optional[str], Dict[str, str]]:
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
    if "outputXML_TXT" in payload:
        payload["outputXML_TXT"] = "XML"
    if "output_format" in payload:
        payload["output_format"] = "XML"
    return action, payload


def _fetch_docket_report_multistep(
    http_client: Any,
    case_link: str,
    *,
    case_number_full: Optional[str],
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
    search_payload.setdefault("csnum1", case_number_full)
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
    filter_payload["outputXML_TXT"] = "XML"
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
    confirm = _submit_confirm_form(http_client, filter_response, referer=filter_action_url)
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
    match = re.search(r'href=[\"\\']([^\"\\']*CaseSummary[^\"\\']*)[\"\\']', html_text)
    if match:
        return match.group(1)
    match = re.search(r'href=[\"\\']([^\"\\']*CaseSummary.*?)[\"\\']', html_text)
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


def _extract_attr(attrs: str, name: str) -> Optional[str]:
    match = re.search(rf"{name}\\s*=\\s*[\"']([^\"']*)[\"']", attrs, re.IGNORECASE)
    return match.group(1) if match else None


def _form_supports_xml(html: str) -> bool:
    return re.search(
        r"name=[\"']output_format[\"'][^>]*value=[\"']xml[\"']",
        html,
        re.IGNORECASE,
    ) is not None


def _force_docket_report(
    http_client: Any,
    case_link: str,
    *,
    case_number_full: Optional[str] = None,
) -> Optional[DocketFetchResult]:
    try:
        url = _build_docket_report_url(
            case_link,
            case_number_full=case_number_full,
            case_number=None,
            output_format="XML",
            url_template=None,
        )
    except ValueError:
        return None
    response = http_client.request(
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
