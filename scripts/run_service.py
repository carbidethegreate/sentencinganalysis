#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Any

from sqlalchemy import select

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


def _run_workers_once(app: Any) -> int:
    total_processed = 0

    max_segments = _as_int("BATCH_WORKER_MAX_SEGMENTS", 1, minimum=1)
    batch_worker = PclBatchWorker(
        app.engine,
        app.pcl_tables,
        app.pcl_client,
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
        docket_output=os.environ.get("PACER_DOCKET_OUTPUT", "xml"),
        docket_url_template=os.environ.get("PACER_DOCKET_URL_TEMPLATE"),
    )
    total_processed += docket_worker.run_once(max_jobs=max_jobs)
    total_processed += _run_document_jobs_once(app)
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
    mode = (os.environ.get("SERVICE_MODE") or "web").strip().lower()
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
