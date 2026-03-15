from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
import os
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, urljoin, urlparse

from sqlalchemy import Table, select, update, func
from lxml import html as lxml_html

try:
    import boto3  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    boto3 = None
try:
    from botocore.config import Config  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    Config = None


@dataclass(frozen=True)
class DocumentJob:
    id: int
    case_id: int
    status: str
    documents_total: Optional[int]
    documents_downloaded: Optional[int]


class DocketDocumentWorker:
    def __init__(
        self,
        engine,
        tables: Dict[str, Table],
        *,
        http_client: Any,
        logger: Optional[Any] = None,
        documents_dir: Optional[str] = None,
    ) -> None:
        self._engine = engine
        self._tables = tables
        self._http_client = http_client
        self._logger = logger
        self._documents_dir = documents_dir or os.path.join(os.getcwd(), "pacer_documents")
        self._local_backup_dir = (
            os.environ.get("PACER_DOCUMENTS_LOCAL_BACKUP_DIR") or ""
        ).strip() or None
        self._s3_bucket = os.environ.get("PACER_DOCUMENTS_S3_BUCKET")
        self._s3_prefix = (os.environ.get("PACER_DOCUMENTS_S3_PREFIX") or "").strip().strip("/")

    def run_job(self, job_id: int, max_docs: int = 50) -> int:
        job = self._load_job(job_id)
        if not job:
            return 0
        if job["status"] not in {"queued", "running"}:
            summary = self._job_counts(job_id)
            if int(summary["queued"]) <= 0:
                return 0
        job = self._mark_running(job)
        processed = 0
        items = self._load_items(job["id"], max_docs=max_docs)
        for item in items:
            if item["status"] != "queued":
                continue
            try:
                self._download_item(job, item)
            except Exception as exc:
                self._mark_item_failed(item, str(exc))
            processed += 1
        self._finalize_job(job)
        return processed

    def run_job_batches(
        self,
        job_id: int,
        *,
        max_docs: int = 50,
        max_batches: int = 1,
        max_seconds: Optional[float] = None,
    ) -> Dict[str, int | str]:
        started = time.monotonic()
        total_processed = 0
        batches_run = 0
        while batches_run < max(1, max_batches):
            processed = self.run_job(job_id, max_docs=max_docs)
            total_processed += processed
            batches_run += 1
            summary = self._job_counts(job_id)
            if summary["queued"] <= 0 or processed <= 0:
                break
            if max_seconds is not None and (time.monotonic() - started) >= max_seconds:
                break
        final_summary = self._job_counts(job_id)
        return {
            "processed": total_processed,
            "batches": batches_run,
            "queued_remaining": final_summary["queued"],
            "downloaded": final_summary["downloaded"],
            "failed": final_summary["failed"],
            "status": str(final_summary["status"] or ""),
            "total": final_summary["total"],
        }

    def _load_job(self, job_id: int) -> Optional[Dict[str, Any]]:
        job_table = self._tables["docket_document_jobs"]
        with self._engine.begin() as conn:
            row = (
                conn.execute(select(job_table).where(job_table.c.id == job_id))
                .mappings()
                .first()
            )
        return dict(row) if row else None

    def _load_items(self, job_id: int, max_docs: int) -> List[Dict[str, Any]]:
        items_table = self._tables["docket_document_items"]
        with self._engine.begin() as conn:
            rows = (
                conn.execute(
                    select(items_table)
                    .where(items_table.c.job_id == job_id)
                    .where(items_table.c.status == "queued")
                    .order_by(items_table.c.id.asc())
                    .limit(max_docs)
                )
                .mappings()
                .all()
            )
        return [dict(row) for row in rows]

    def _mark_running(self, job: Dict[str, Any]) -> Dict[str, Any]:
        job_table = self._tables["docket_document_jobs"]
        now = datetime.utcnow()
        updates = {"status": "running", "finished_at": None, "last_error": None}
        if not job.get("started_at"):
            updates["started_at"] = now
        with self._engine.begin() as conn:
            conn.execute(
                update(job_table).where(job_table.c.id == job["id"]).values(**updates)
            )
        job.update(updates)
        return job

    def _mark_item_failed(self, item: Dict[str, Any], message: str) -> None:
        items_table = self._tables["docket_document_items"]
        now = datetime.utcnow()
        updates = {"status": "failed", "error": message, "updated_at": now}
        with self._engine.begin() as conn:
            conn.execute(
                update(items_table).where(items_table.c.id == item["id"]).values(**updates)
            )
        if self._logger:
            self._logger.warning("Document download failed: %s", message)

    def _download_item(self, job: Dict[str, Any], item: Dict[str, Any]) -> None:
        url = item.get("source_url")
        if not url:
            raise ValueError("Missing source URL for document.")
        request_method = str(item.get("request_method") or "GET").strip().upper()
        if request_method not in {"GET", "POST"}:
            request_method = "GET"
        raw_payload = _decode_raw_payload(item.get("request_payload_json"))
        payload = _decode_request_payload(item.get("request_payload_json"))
        targets = _build_request_targets(url, request_method, raw_payload)
        retries, backoff = _download_retry_config()
        last_error = None
        for attempt in range(retries + 1):
            try:
                target_errors: List[str] = []
                response = None
                used_url = url
                for target in targets:
                    try:
                        method = target["method"]
                        target_url = target["url"]
                        headers = {
                            "Accept": "application/pdf, text/html",
                            # PACER doc links can reject missing/foreign referrers.
                            "Referer": "https://external",
                        }
                        request_data = None
                        if method == "POST":
                            if not payload:
                                raise ValueError("Missing POST payload for goDLS document request.")
                            headers["Content-Type"] = "application/x-www-form-urlencoded"
                            request_data = urlencode(payload).encode("utf-8")
                        candidate = self._http_client.request(
                            method,
                            target_url,
                            headers=headers,
                            data=request_data,
                            include_cookie=True,
                        )
                        if candidate.status_code != 200:
                            raise ValueError(f"Download failed with status {candidate.status_code}.")
                        candidate = _resolve_document_response(
                            self._http_client,
                            target_url,
                            candidate,
                            payload,
                            headers,
                        )
                        if candidate.status_code != 200:
                            raise ValueError(f"Download failed with status {candidate.status_code}.")
                        response = candidate
                        used_url = target_url
                        break
                    except Exception as target_exc:
                        target_errors.append(f"{target['method']} {target['url']}: {target_exc}")
                if response is None:
                    raise ValueError(" | ".join(target_errors) if target_errors else "Document request failed.")
                content_type = response.headers.get("Content-Type", "")
                gate_reason = _classify_non_document_response(content_type, response.body)
                if gate_reason:
                    raise ValueError(
                        "Downloaded PACER HTML instead of the actual pleading "
                        f"({gate_reason})."
                    )
                filename = _build_filename(
                    job["case_id"],
                    item.get("document_number"),
                    item["id"],
                    content_type=content_type,
                )
                stored_path = self._store_document(job["case_id"], filename, response.body)
                items_table = self._tables["docket_document_items"]
                now = datetime.utcnow()
                updates = {
                    "status": "downloaded",
                    "file_path": stored_path,
                    "content_type": content_type,
                    "bytes": len(response.body),
                    "downloaded_at": now,
                    "updated_at": now,
                    "error": None,
                }
                with self._engine.begin() as conn:
                    conn.execute(
                        update(items_table)
                        .where(items_table.c.id == item["id"])
                        .values(**updates)
                    )
                if self._logger and used_url != url:
                    self._logger.info(
                        "Document item %s downloaded via fallback URL %s (primary=%s).",
                        item.get("id"),
                        used_url,
                        url,
                    )
                return
            except Exception as exc:
                last_error = str(exc)
                if attempt < retries:
                    time.sleep(backoff * (2 ** attempt))
                else:
                    raise ValueError(last_error) from exc

    def _store_document(self, case_id: int, filename: str, data: bytes) -> str:
        local_path = _write_local(self._documents_dir, case_id, filename, data)
        if self._local_backup_dir and not _same_local_directory(
            self._local_backup_dir,
            self._documents_dir,
        ):
            _write_local(self._local_backup_dir, case_id, filename, data)
        if self._s3_bucket:
            return _write_s3(self._s3_bucket, self._s3_prefix, case_id, filename, data)
        return local_path

    def _finalize_job(self, job: Dict[str, Any]) -> None:
        summary = self._job_counts(job["id"])
        items_table = self._tables["docket_document_items"]
        job_table = self._tables["docket_document_jobs"]
        with self._engine.begin() as conn:
            total = int(summary["total"])
            downloaded = int(summary["downloaded"])
            failed = int(summary["failed"])
            queued = int(summary["queued"])
            processing = int(summary["processing"])
            last_error = None
            if failed:
                last_error = conn.execute(
                    select(items_table.c.error)
                    .where(
                        (items_table.c.job_id == job["id"])
                        & (items_table.c.status == "failed")
                    )
                    .order_by(items_table.c.updated_at.desc())
                    .limit(1)
                ).scalar()
            now = datetime.utcnow()
            if queued:
                status = "queued"
                finished_at = None
            elif processing:
                status = "running"
                finished_at = None
            else:
                status = "completed_with_errors" if failed else "completed"
                finished_at = now
            updates = {
                "documents_total": total,
                "documents_downloaded": downloaded,
                "finished_at": finished_at,
                "status": status,
                "last_error": last_error,
                "updated_at": now,
            }
            conn.execute(
                update(job_table).where(job_table.c.id == job["id"]).values(**updates)
            )

    def _job_counts(self, job_id: int) -> Dict[str, int | str]:
        items_table = self._tables["docket_document_items"]
        job_table = self._tables["docket_document_jobs"]
        with self._engine.begin() as conn:
            total = int(
                conn.execute(
                    select(func.count()).select_from(items_table).where(
                        items_table.c.job_id == job_id
                    )
                ).scalar()
                or 0
            )
            downloaded = int(
                conn.execute(
                    select(func.count()).select_from(items_table).where(
                        (items_table.c.job_id == job_id)
                        & (items_table.c.status == "downloaded")
                    )
                ).scalar()
                or 0
            )
            failed = int(
                conn.execute(
                    select(func.count()).select_from(items_table).where(
                        (items_table.c.job_id == job_id)
                        & (items_table.c.status == "failed")
                    )
                ).scalar()
                or 0
            )
            queued = int(
                conn.execute(
                    select(func.count()).select_from(items_table).where(
                        (items_table.c.job_id == job_id)
                        & (items_table.c.status == "queued")
                    )
                ).scalar()
                or 0
            )
            processing = int(
                conn.execute(
                    select(func.count()).select_from(items_table).where(
                        (items_table.c.job_id == job_id)
                        & (items_table.c.status.in_(["processing", "running"]))
                    )
                ).scalar()
                or 0
            )
            status = (
                conn.execute(
                    select(job_table.c.status).where(job_table.c.id == job_id).limit(1)
                ).scalar()
                or ""
            )
        return {
            "total": total,
            "downloaded": downloaded,
            "failed": failed,
            "queued": queued,
            "processing": processing,
            "status": str(status or ""),
        }


def _build_filename(
    case_id: int,
    doc_number: Optional[str],
    item_id: int,
    *,
    content_type: str,
) -> str:
    ext = ".pdf"
    if "text/html" in (content_type or "").lower():
        ext = ".html"
    if doc_number:
        safe = re.sub(r"[^a-zA-Z0-9_-]+", "_", str(doc_number))
        return f"case_{case_id}_doc_{safe}_{item_id}{ext}"
    return f"case_{case_id}_doc_{item_id}{ext}"


def _download_retry_config() -> tuple[int, float]:
    retries_raw = os.environ.get("PACER_DOCUMENT_DOWNLOAD_RETRIES", "2")
    backoff_raw = os.environ.get("PACER_DOCUMENT_DOWNLOAD_BACKOFF", "2.0")
    try:
        retries = max(0, int(retries_raw))
    except ValueError:
        retries = 2
    try:
        backoff = max(0.5, float(backoff_raw))
    except ValueError:
        backoff = 2.0
    return retries, backoff


def _decode_request_payload(raw_payload: Optional[str]) -> Dict[str, str]:
    parsed = _decode_raw_payload(raw_payload)
    if not parsed:
        return {}
    allowed_keys = [
        "caseid",
        "de_seq_num",
        "got_receipt",
        "pdf_header",
        "pdf_toggle_possible",
        "magic_num",
        "claim_id",
        "claim_num",
        "claim_doc_seq",
        "hdr",
    ]
    payload: Dict[str, str] = {}
    for key in allowed_keys:
        value = parsed.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if not text:
            continue
        payload[key] = text
    return payload


def _decode_raw_payload(raw_payload: Optional[str]) -> Dict[str, str]:
    if not raw_payload:
        return {}
    try:
        parsed = json.loads(raw_payload)
    except (TypeError, json.JSONDecodeError):
        return {}
    if not isinstance(parsed, dict):
        return {}
    values: Dict[str, str] = {}
    for key, value in parsed.items():
        if value is None:
            continue
        text = str(value).strip()
        if text:
            values[str(key)] = text
    return values


def _build_request_targets(
    source_url: str,
    request_method: str,
    raw_payload: Dict[str, str],
) -> List[Dict[str, str]]:
    method = request_method if request_method in {"GET", "POST"} else "GET"
    targets: List[Dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add_target(target_method: str, target_url: str) -> None:
        key = (target_method, target_url)
        if not target_url or key in seen:
            return
        seen.add(key)
        targets.append({"method": target_method, "url": target_url})

    add_target(method, source_url)
    form_post_url = raw_payload.get("form_post_url")
    if form_post_url:
        add_target("POST", form_post_url)

    # Some PACER dockets expose transient /doc1 links; /cgi-bin/show_doc.pl with
    # case/de_seq metadata is often the more stable route.
    caseid = raw_payload.get("caseid", "")
    de_seq_num = raw_payload.get("de_seq_num", "")
    parsed = urlparse(source_url or "")
    if parsed.scheme and parsed.netloc and caseid and de_seq_num:
        base = f"{parsed.scheme}://{parsed.netloc}"
        show_doc_url = f"{base}/cgi-bin/show_doc.pl"
        add_target("POST", show_doc_url)
        query_url = (
            f"{show_doc_url}?caseid={caseid}&de_seq_num={de_seq_num}&pdf_header=1"
        )
        add_target("GET", query_url)
    return targets


def _is_html_response(content_type: str, body: bytes) -> bool:
    lowered = (content_type or "").lower()
    if "text/html" in lowered:
        return True
    sample = (body or b"")[:256].decode("utf-8", errors="ignore").lower()
    return "<html" in sample or "<!doctype html" in sample


def _decode_html_bytes(body: bytes) -> str:
    return (body or b"").decode("utf-8", errors="replace")


def _normalize_visible_html_text(raw_html: str) -> str:
    if not raw_html:
        return ""
    try:
        tree = lxml_html.fromstring(raw_html)
    except Exception:
        return re.sub(r"\s+", " ", raw_html).strip()
    for bad in tree.xpath("//script|//style|//noscript|//head"):
        bad.drop_tree()
    return re.sub(r"\s+", " ", tree.text_content() or "").strip()


def _extract_hidden_inputs(tree: Any) -> Dict[str, str]:
    values: Dict[str, str] = {}
    for node in tree.xpath("//form//input[@name]"):
        name = (node.get("name") or "").strip()
        if not name:
            continue
        value = node.get("value")
        values[name] = "" if value is None else str(value)
    return values


def _extract_first_form(tree: Any) -> Optional[tuple[str, str]]:
    forms = tree.xpath("//form")
    if not forms:
        return None
    form = forms[0]
    action = (form.get("action") or "").strip()
    method = (form.get("method") or "GET").strip().upper() or "GET"
    return action, method


def _looks_like_referrer_warning(html_text: str) -> bool:
    lowered = (html_text or "").lower()
    return (
        "link to this page may not have originated from within cm/ecf" in lowered
        and "referrer_form" in lowered
    )


def _looks_like_receipt_gate(html_text: str) -> bool:
    lowered = (html_text or "").lower()
    return "transaction receipt" in lowered and "view document" in lowered


def _extract_receipt_continue_url(html_text: str, base_url: str) -> str:
    patterns = [
        r"parent\.location='([^']*got_receipt=1[^']*)'",
        r"location\.href='([^']*got_receipt=1[^']*)'",
        r"href=['\"]([^'\"]*got_receipt=1[^'\"]*)['\"]",
    ]
    for pattern in patterns:
        match = re.search(pattern, html_text or "", re.IGNORECASE)
        if not match:
            continue
        raw = (match.group(1) or "").strip()
        if raw:
            return urljoin(base_url, raw)
    return ""


def _find_embedded_document_url(tree: Any, base_url: str) -> str:
    candidates: List[str] = []
    for xpath_expr in ("//iframe/@src", "//embed/@src", "//a/@href"):
        for raw in tree.xpath(xpath_expr):
            link = str(raw or "").strip()
            if not link:
                continue
            lowered = link.lower()
            if (
                "show_temp.pl" in lowered
                or lowered.endswith(".pdf")
                or "type=application/pdf" in lowered
            ):
                candidates.append(urljoin(base_url, link))
    return candidates[0] if candidates else ""


def _extract_multidoc_url(html_text: str, base_url: str) -> str:
    match = re.search(
        r"submit_form\(\s*0\s*,\s*'([^']*show_multidocs\.pl[^']*)'",
        html_text or "",
        re.IGNORECASE,
    )
    if not match:
        return ""
    value = (match.group(1) or "").strip()
    if not value:
        return ""
    return urljoin(base_url, value)


def _classify_non_document_response(content_type: str, body: bytes) -> str:
    if not _is_html_response(content_type, body):
        return ""
    raw_html = _decode_html_bytes(body)
    visible_text = _normalize_visible_html_text(raw_html)
    lowered_raw = raw_html.lower()
    lowered_text = visible_text.lower()

    if "csologin/login.jsf" in lowered_raw:
        return "pacer_login_redirect"
    if "log in to pacer systems" in lowered_text or "district court login" in lowered_text:
        return "pacer_login_page"
    if "you do not have permission to view this document" in lowered_text:
        return "document_permission_denied"
    if "this document is not available" in lowered_text:
        return "document_unavailable"
    if (
        "public access to court electronic records" in lowered_text
        and "pacer" in lowered_text
    ):
        return "pacer_home_page"
    if (
        "query reports utilities" in lowered_text
        and "log out" in lowered_text
        and "document unavailable" in lowered_text
    ):
        return "cmecf_unavailable_page"
    return ""


def _resolve_document_response(
    http_client: Any,
    request_url: str,
    initial_response: Any,
    payload: Dict[str, str],
    headers: Dict[str, str],
) -> Any:
    response = initial_response
    max_hops = 4
    for _ in range(max_hops):
        body = response.body or b""
        content_type = response.headers.get("Content-Type", "")
        if not _is_html_response(content_type, body):
            return response

        html_text = _decode_html_bytes(body)
        try:
            tree = lxml_html.fromstring(html_text)
        except Exception:
            return response

        embedded_url = _find_embedded_document_url(tree, request_url)
        if embedded_url:
            response = http_client.request(
                "GET",
                embedded_url,
                headers={"Accept": "application/pdf, text/html", "Referer": request_url},
                include_cookie=True,
            )
            continue

        if _looks_like_referrer_warning(html_text):
            form = _extract_first_form(tree)
            if not form:
                return response
            action, method = form
            target_url = urljoin(request_url, action) if action else request_url
            form_payload = _extract_hidden_inputs(tree)
            form_headers = {"Accept": "application/pdf, text/html", "Referer": "https://external"}
            encoded = None
            if method == "POST":
                form_headers["Content-Type"] = "application/x-www-form-urlencoded"
                encoded = urlencode(form_payload).encode("utf-8")
            response = http_client.request(
                method,
                target_url,
                headers=form_headers,
                data=encoded,
                include_cookie=True,
            )
            continue

        if _looks_like_receipt_gate(html_text):
            continue_url = _extract_receipt_continue_url(html_text, request_url)
            if continue_url:
                response = http_client.request(
                    "GET",
                    continue_url,
                    headers={"Accept": "application/pdf, text/html", "Referer": request_url},
                    include_cookie=True,
                )
                continue
            receipt_payload = dict(payload)
            receipt_payload["got_receipt"] = "1"
            response = http_client.request(
                "POST",
                request_url,
                headers=headers,
                data=urlencode(receipt_payload).encode("utf-8"),
                include_cookie=True,
            )
            continue

        multidoc_url = _extract_multidoc_url(html_text, request_url)
        if multidoc_url:
            separator = "&" if "?" in multidoc_url else "?"
            if "zipit=" not in multidoc_url:
                multidoc_url = f"{multidoc_url}{separator}exclude_attachments=&zipit=0"
            response = http_client.request(
                "GET",
                multidoc_url,
                headers={"Accept": "application/pdf, text/html", "Referer": request_url},
                include_cookie=True,
            )
            continue

        return response
    return response


def _s3_key(prefix: str, case_id: int, filename: str) -> str:
    base = f"case_{case_id}/{filename}"
    if not prefix:
        return base
    return f"{prefix}/{base}"


def _ensure_s3_client():
    if boto3 is None:
        raise ValueError("boto3 is required for S3 storage but is not installed.")
    endpoint_url = (os.environ.get("PACER_DOCUMENTS_S3_ENDPOINT_URL") or "").strip() or None
    region_name = (os.environ.get("PACER_DOCUMENTS_S3_REGION") or "").strip() or None
    access_key_id = (os.environ.get("PACER_DOCUMENTS_S3_ACCESS_KEY_ID") or "").strip() or None
    secret_access_key = (
        os.environ.get("PACER_DOCUMENTS_S3_SECRET_ACCESS_KEY") or ""
    ).strip() or None

    kwargs: Dict[str, Any] = {}
    if endpoint_url:
        kwargs["endpoint_url"] = endpoint_url
    if region_name:
        kwargs["region_name"] = region_name
    if access_key_id and secret_access_key:
        kwargs["aws_access_key_id"] = access_key_id
        kwargs["aws_secret_access_key"] = secret_access_key
    if Config is not None:
        kwargs["config"] = Config(signature_version="s3v4")
    return boto3.client("s3", **kwargs)


def _write_local(documents_dir: str, case_id: int, filename: str, data: bytes) -> str:
    target_dir = os.path.join(documents_dir, f"case_{case_id}")
    os.makedirs(target_dir, exist_ok=True)
    target_path = os.path.join(target_dir, filename)
    with open(target_path, "wb") as handle:
        handle.write(data)
    return target_path


def _same_local_directory(left: str, right: str) -> bool:
    left_value = os.path.abspath(os.path.expanduser(left or ""))
    right_value = os.path.abspath(os.path.expanduser(right or ""))
    return bool(left_value) and left_value == right_value


def _write_s3(bucket: str, prefix: str, case_id: int, filename: str, data: bytes) -> str:
    client = _ensure_s3_client()
    key = _s3_key(prefix, case_id, filename)
    client.put_object(Bucket=bucket, Key=key, Body=data)
    return f"s3://{bucket}/{key}"
