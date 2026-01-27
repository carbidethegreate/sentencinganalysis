from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import os
import re
from typing import Any, Dict, List, Optional

from sqlalchemy import Table, select, update, func


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

    def run_job(self, job_id: int, max_docs: int = 50) -> int:
        job = self._load_job(job_id)
        if not job:
            return 0
        if job["status"] not in {"queued", "running"}:
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
        updates = {"status": "running", "started_at": now, "last_error": None}
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
        response = self._http_client.request(
            "GET",
            url,
            headers={"Accept": "application/pdf"},
            include_cookie=True,
        )
        if response.status_code != 200:
            raise ValueError(f"Download failed with status {response.status_code}.")
        content_type = response.headers.get("Content-Type", "")
        filename = _build_filename(
            job["case_id"],
            item.get("document_number"),
            item["id"],
            content_type=content_type,
        )
        target_dir = os.path.join(self._documents_dir, f"case_{job['case_id']}")
        os.makedirs(target_dir, exist_ok=True)
        target_path = os.path.join(target_dir, filename)
        with open(target_path, "wb") as handle:
            handle.write(response.body)
        items_table = self._tables["docket_document_items"]
        now = datetime.utcnow()
        updates = {
            "status": "downloaded",
            "file_path": target_path,
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

    def _finalize_job(self, job: Dict[str, Any]) -> None:
        items_table = self._tables["docket_document_items"]
        job_table = self._tables["docket_document_jobs"]
        with self._engine.begin() as conn:
            total = int(
                conn.execute(
                    select(func.count()).select_from(items_table).where(
                        items_table.c.job_id == job["id"]
                    )
                ).scalar()
                or 0
            )
            downloaded = int(
                conn.execute(
                    select(func.count()).select_from(items_table).where(
                        (items_table.c.job_id == job["id"])
                        & (items_table.c.status == "downloaded")
                    )
                ).scalar()
                or 0
            )
            failed = int(
                conn.execute(
                    select(func.count()).select_from(items_table).where(
                        (items_table.c.job_id == job["id"])
                        & (items_table.c.status == "failed")
                    )
                ).scalar()
                or 0
            )
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
            status = "completed_with_errors" if failed else "completed"
            updates = {
                "documents_total": total,
                "documents_downloaded": downloaded,
                "finished_at": now,
                "status": status,
                "last_error": last_error,
                "updated_at": now,
            }
            conn.execute(
                update(job_table).where(job_table.c.id == job["id"]).values(**updates)
            )


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
