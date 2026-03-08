#!/usr/bin/env python3
from __future__ import annotations

import os
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from sqlalchemy import func, or_, select

# Ensure project root is importable when this file is invoked directly.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app
from docket_documents import DocketDocumentWorker
from docket_enrichment import DocketEnrichmentWorker
from pcl_batch import PclBatchWorker


def _as_int(name: str, default: int, minimum: int = 1) -> int:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        parsed = int(raw)
    except ValueError:
        return default
    return max(minimum, parsed)


def _as_float(name: str, default: float) -> float:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _as_bool(name: str, default: bool) -> bool:
    raw = (os.environ.get(name) or "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on", "y"}


def _run_web() -> None:
    port = str(_as_int("PORT", 5000, minimum=1))
    timeout = str(_as_int("GUNICORN_TIMEOUT", 180, minimum=30))
    os.execvp(
        "gunicorn",
        [
            "gunicorn",
            "--bind",
            f"0.0.0.0:{port}",
            "--timeout",
            timeout,
            "app:create_app()",
        ],
    )


def _run_document_jobs_once(app: Any) -> int:
    jobs_table = app.pcl_tables.get("docket_document_jobs")
    if jobs_table is None:
        return 0
    max_jobs = _as_int("DOCUMENT_WORKER_MAX_JOBS", 5, minimum=1)
    max_docs = _as_int("DOCUMENT_WORKER_MAX_DOCS", 50, minimum=1)
    with app.engine.begin() as conn:
        rows = (
            conn.execute(
                select(jobs_table.c.id)
                .where(jobs_table.c.status.in_(["queued", "running"]))
                .order_by(jobs_table.c.created_at.asc(), jobs_table.c.id.asc())
                .limit(max_jobs)
            )
            .mappings()
            .all()
        )
    if not rows:
        return 0
    worker = DocketDocumentWorker(
        app.engine,
        app.pcl_tables,
        http_client=app.pcl_background_http_client,
        logger=app.logger,
        documents_dir=os.environ.get("PACER_DOCUMENTS_DIR"),
    )
    processed = 0
    for row in rows:
        processed += worker.run_job(int(row["id"]), max_docs=max_docs)
    return processed


def _run_document_text_jobs_once(app: Any) -> int:
    if not _as_bool("DOCUMENT_TEXT_WORKER_ENABLED", True):
        return 0
    if app.engine.dialect.name != "postgresql":
        return 0
    items_table = app.pcl_tables.get("docket_document_items")
    if items_table is None:
        return 0

    max_items = _as_int("DOCUMENT_TEXT_WORKER_LIMIT", 25, minimum=1)
    retry_below_confidence = _as_float("DOCUMENT_TEXT_RETRY_BELOW_CONFIDENCE", 0.88)
    openai_threshold = _as_float("DOCUMENT_TEXT_OPENAI_THRESHOLD", 0.90)
    openai_verify = _as_bool("DOCUMENT_TEXT_OPENAI_VERIFY", True)

    ocr_max_pages_raw = (os.environ.get("DOCUMENT_TEXT_OCR_MAX_PAGES") or "").strip()
    try:
        ocr_max_pages = int(ocr_max_pages_raw) if ocr_max_pages_raw else 0
    except ValueError:
        ocr_max_pages = 0
    ocr_max_pages = max(0, ocr_max_pages)

    with app.engine.begin() as conn:
        pending = int(
            conn.execute(
                select(func.count()).select_from(items_table).where(
                    items_table.c.status == "downloaded",
                    or_(
                        items_table.c.text_status.is_(None),
                        items_table.c.text_status.in_(["queued", "processing", "retry"]),
                        func.coalesce(items_table.c.text_confidence, 0.0)
                        < retry_below_confidence,
                    ),
                )
            ).scalar()
            or 0
        )
    if pending <= 0:
        return 0

    db_url = app.engine.url.render_as_string(hide_password=False)
    if db_url.startswith("postgresql+psycopg://"):
        db_url = "postgresql://" + db_url.split("://", 1)[1]
    elif db_url.startswith("postgresql+psycopg2://"):
        db_url = "postgresql://" + db_url.split("://", 1)[1]
    script_path = PROJECT_ROOT / "scripts" / "extract_docket_document_texts.py"
    cmd = [
        sys.executable,
        str(script_path),
        "--db-url",
        db_url,
        "--limit",
        str(max_items),
        "--retry-below-confidence",
        str(retry_below_confidence),
        "--openai-threshold",
        str(openai_threshold),
        "--ocr-max-pages",
        str(ocr_max_pages),
    ]
    if openai_verify:
        cmd.append("--openai-verify")

    timeout_seconds = _as_int("DOCUMENT_TEXT_WORKER_TIMEOUT_SECONDS", 1200, minimum=30)
    done = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
    )
    output = (done.stdout or "").strip()
    errors = (done.stderr or "").strip()
    summary: dict[str, Any] = {}
    if output:
        match = re.search(r"(\{[\s\S]*\})\s*$", output)
        if match:
            try:
                summary = json.loads(match.group(1))
            except json.JSONDecodeError:
                summary = {}
    processed = int(summary.get("processed") or 0)
    failed = int(summary.get("failed") or 0)
    if done.returncode != 0 and processed == 0 and failed == 0:
        app.logger.warning(
            "Document text extraction script failed (exit=%s). stderr=%s stdout=%s",
            done.returncode,
            errors[-1200:],
            output[-1200:],
        )
        return 0
    if processed or failed:
        app.logger.info(
            "Document text extraction: processed=%s failed=%s pending_before=%s",
            processed,
            failed,
            pending,
        )
    return processed + failed


def _run_workers_once(app: Any) -> int:
    total_processed = 0

    max_segments = _as_int("BATCH_WORKER_MAX_SEGMENTS", 1, minimum=1)
    batch_worker = PclBatchWorker(
        app.engine,
        app.pcl_tables,
        app.pcl_background_client,
        logger=app.logger,
        sleep_fn=time.sleep,
    )
    total_processed += batch_worker.run_once(max_segments=max_segments)

    max_jobs = _as_int("DOCKET_WORKER_MAX_JOBS", 5, minimum=1)
    docket_worker = DocketEnrichmentWorker(
        app.engine,
        app.pcl_tables,
        logger=app.logger,
        endpoint_available=True,
        http_client=app.pcl_background_http_client,
        docket_output=os.environ.get("PACER_DOCKET_OUTPUT", "html"),
        docket_url_template=os.environ.get("PACER_DOCKET_URL_TEMPLATE"),
    )
    total_processed += docket_worker.run_once(max_jobs=max_jobs)
    total_processed += _run_document_jobs_once(app)
    total_processed += _run_document_text_jobs_once(app)
    return total_processed


def _run_worker_loop() -> None:
    app = create_app()
    interval_seconds = _as_int("WORKER_LOOP_INTERVAL_SECONDS", 30, minimum=5)
    while True:
        processed = _run_workers_once(app)
        app.logger.info("Worker loop processed %s items.", processed)
        time.sleep(interval_seconds)


def _run_cron_once() -> None:
    app = create_app()
    processed = _run_workers_once(app)
    app.logger.info("Cron run processed %s items.", processed)


def main() -> None:
    mode = (os.environ.get("SERVICE_MODE") or "").strip().lower()
    # Some Render services use Secret Files (/etc/secrets) rather than env vars,
    # so SERVICE_MODE may be unset. Fall back to Render's service type to keep
    # worker/cron instances doing the right thing.
    if not mode:
        render_service_type = (os.environ.get("RENDER_SERVICE_TYPE") or "").strip().lower()
        if render_service_type == "worker":
            mode = "worker"
        elif render_service_type in {"cron", "cron_job"}:
            mode = "cron"
        else:
            mode = "web"
    if mode == "web":
        _run_web()
        return
    if mode == "worker":
        _run_worker_loop()
        return
    if mode == "cron":
        _run_cron_once()
        return
    raise SystemExit(f"Unknown SERVICE_MODE={mode!r}. Expected one of: web, worker, cron.")


if __name__ == "__main__":
    main()
