from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import html
import json
import re
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlencode, urljoin, urlparse
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
                case_office=case_row.get("case_office"),
                case_year=case_row.get("case_year"),
                case_type=case_row.get("case_type"),
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
                        output_format="xml",
                    )
                    if multistep:
                        if _looks_like_docket_shell(
                            multistep.body.decode("utf-8", errors="replace")
                        ):
                            multistep_html = _fetch_docket_report_multistep(
                                self._http_client,
                                case_row["case_link"],
                                case_number_full=case_row.get("case_number_full"),
                                case_office=case_row.get("case_office"),
                                case_year=case_row.get("case_year"),
                                case_type=case_row.get("case_type"),
                                case_number=case_row.get("case_number"),
                                output_format="html",
                            )
                            if multistep_html:
                                return multistep_html
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
        header_fields: Optional[Dict[str, Any]] = None,
        force_store_html: bool = False,
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
    except (ValueError, TypeError):
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
    if not raw:
        return ""
    try:
        tree = lxml_html.fromstring(raw)
    except (ValueError, TypeError):
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


def _extract_links_from_cell(cell: Any, *, base_url: Optional[str]) -> List[Dict[str, str]]:
    links: List[Dict[str, str]] = []
    for anchor in cell.xpath(".//a[@href]"):
        href = (anchor.get("href") or "").strip()
        if not href:
            continue
        label = _normalize_html_text(anchor)
        if base_url:
            href = _resolve_link(base_url, href)
        link = {"href": href}
        if label:
            link["label"] = label
        links.append(link)
    return links


def _resolve_link(base_url: str, href: str) -> str:
    return urljoin(base_url, href)


def _extract_docket_header_fields_from_html(html_text: str) -> Dict[str, Any]:
    if not html_text:
        return {}
    try:
        tree = lxml_html.fromstring(html_text)
    except (ValueError, TypeError):
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
    criteria = _extract_selection_criteria(tree)
    if criteria:
        header_fields["selection_criteria"] = criteria
    return header_fields


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
    selection = header_fields.get("selection_criteria")
    if isinstance(selection, dict):
        for key, value in selection.items():
            parts.append(f"{key}: {value}")
    return " | ".join(parts)


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
) -> Optional[DocketFetchResult]:
    action, payload, form_html = _select_docket_form(html)
    if not action or not payload:
        return None
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
        payload.setdefault("case_number_text_area_0", case_number_full)
        payload.setdefault("case_num", case_number_full)
    if formatted_case_number:
        payload["case_num"] = formatted_case_number
        payload["case_number_text_area_0"] = formatted_case_number
    if case_id and "case_number_text_area_0" not in payload:
        payload["case_number_text_area_0"] = case_id
    if "case_number_text_area_0" not in payload and case_number:
        payload["case_number_text_area_0"] = case_number
    if case_id and "all_case_ids" not in payload:
        payload["all_case_ids"] = case_id
    payload.setdefault("date_range_type", "Filed")
    payload.setdefault("date_from", "1/1/1960")
    payload.setdefault("date_to", "")
    payload.setdefault("documents_numbered_from_", "")
    payload.setdefault("documents_numbered_to_", "")
    payload.setdefault("report_type", "docket")
    payload.setdefault("sort1", "oldest date first")
    payload.setdefault("sort2", "")

    output_format = payload.get("output_format", "")
    if output_format:
        output_format = output_format.lower()
    if output_format not in {"xml", "html", "pdf"}:
        output_format = "xml" if _form_supports_xml(form_html or html) else "html"

    def _submit_with_format(fmt: str) -> DocketFetchResult:
        local_payload = dict(payload)
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
        encoded = urlencode(local_payload).encode("utf-8")
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
        followup = _submit_confirm_form(
            http_client,
            response,
            referer=action_url,
            desired_output=fmt,
        )
        if followup is not None:
            followup.form_payload = local_payload
            return followup
        content_type = response.headers.get("Content-Type", "")
        return DocketFetchResult(
            url=action_url,
            status_code=response.status_code,
            content_type=content_type,
            body=response.body,
            form_action=action_url,
            form_payload=local_payload,
        )

    result = _submit_with_format(output_format)
    if output_format == "xml":
        if _looks_like_docket_shell(result.body.decode("utf-8", errors="replace")):
            return _submit_with_format("html")
    return result


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
