# PACER → PCL pipeline plan

## Goal
Provide an implementation map for adding PACER Case Locator (PCL) batch indexing with optional per-case docket enrichment, aligned to the existing admin PACER flow and Render deployment configuration.

## Current state inventory (grounded in repo)

### Flask app factory and routing
- App factory lives in `app.py:create_app()` and wires up all routes, helpers, and SQLAlchemy tables in a single module (no blueprints present). This is the primary entry point used by the Docker `CMD` (`gunicorn ... 'app:create_app()'`) and by local `__main__` execution. (`app.py`, `Dockerfile`)

### Admin PACER routes and templates
- Admin PACER landing flow is implemented in `app.py`:
  - `admin_federal_data_dashboard_get_pacer_data()` renders the PACER auth page and passes PACER state to the template.
  - `admin_federal_data_dashboard_pacer_auth()` posts to the PACER auth client and stores PACER session data in memory.
  - `admin_federal_data_dashboard_pacer_logout()` clears the in-memory PACER session.
  - Placeholder routes exist for `pcl-batch-search` and `expand-existing`.
- Templates are in `templates/`:
  - `admin_federal_data_get_pacer_data.html` renders the PACER auth form and the “PCL Batch Search” and “Expand Existing PCL Data” links.
  - `admin_federal_data_base.html` and `admin_federal_data_placeholder.html` provide the admin dashboard layout.

### PACER auth client and HTTP wrapper
- PACER auth client is implemented in `app.py` as `PacerAuthClient` and helpers:
  - `build_pacer_auth_payload()` builds the JSON payload.
  - `PacerAuthClient.authenticate()` uses `urllib.request` to POST to `/services/cso-auth` on the configured PACER auth base URL.
  - `interpret_pacer_auth_response()` interprets auth responses and MFA/client-code requirements.
- PACER session token (`nextGenCSO`) is stored in the in-memory `pacer_sessions` dict and used for subsequent PCL API calls (comment in `_set_pacer_session()`).

### Existing DB models and schema management
- Database schema is defined inline in `app.py` using `sqlalchemy.Table` definitions: `users`, `newsletter_subscriptions`, `case_stage1`, and `case_data_one`.
- Schema creation uses `metadata.create_all(...)` at startup, with ad-hoc column checks via `_ensure_table_columns()` for incremental additions.
- There is no Alembic migration system or separate models module currently; schema is bootstrapped directly in the app factory.

### Render services, containers, and cron/worker entry points
- `render.yaml` defines multiple services, including:
  - `sentencinganalysis_python_3` (Python web, `gunicorn app:app`).
  - Docker-based services (`CourtDataPro`, `sentencinganalysis` worker, cron) using `Dockerfile`.
  - A cron service scheduled every 5 minutes that uses the same Dockerfile.
- `Dockerfile` runs gunicorn with `app:create_app()` by default.

### Environment variable loading & DB URL configuration
- Environment variables are accessed via `_first_env_or_secret_file()` in `app.py`, supporting direct env vars, `*_FILE` overrides, or `/etc/secrets/<name>` values.
- Database URL is derived by `build_database_url()` in `app.py`:
  - Prefer `DATABASE_URL` or Render-provided variants.
  - Fallback to discrete `Hostname`/`Port`/`Database`/`Username`/`Password` values.
  - Final fallback to a local SQLite file (`case_filed_rpt.sqlite`) via `DB_PATH` or module-relative path.

### Background job patterns
- Background processing is done via in-process threads (no external queue):
  - `threading.Thread(..., daemon=True)` runs `_process_case_stage1_upload` and `_process_case_data_one_upload` after file uploads.
- No Celery/RQ/APScheduler is present; there are no worker queues beyond Render cron and in-process threads.

### PCL API documentation in repo
- PCL API documentation is committed in `PCL-API-Document_4.md`.
- PACER auth API reference lives in `PACER_Authentication_API-2025_v2_0.md`.

## Target state (for PCL batch indexing & docket enrichment)

### PCL batch indexing
- Introduce a PCL batch search workflow that:
  - Uses existing PACER auth (token from `/services/cso-auth`) for PCL API calls.
  - Creates a batch search job in PCL, polls job status, and downloads results.
  - Stores receipts (report IDs, timestamps), cost data (if provided by PCL), and raw payload metadata.

### Optional per-case enrichment
- For selected results, optionally query case-specific endpoints for docket or parties and attach enriched metadata to existing case records.
- Provide controls in the admin UI to enable/disable enrichment on a per-run basis, with safe defaults.

### Admin UI updates
- Add admin dashboard cards for:
  - “PCL Batch Indexing” (start job, see status, download results).
  - “PCL Enrichment” (select cases to enrich, schedule run).
  - “Receipts & Cost Tracking” (PCL job receipts and totals).
- Extend the existing “Case Cards”/search interfaces to display PCL enrichment metadata.

## Stepwise implementation plan (no code changes yet)

> Each step lists the exact files to touch or create. This plan is scoped for follow-on prompts.

1. **Add structured PCL client & config**
   - Create a dedicated PCL client module (e.g., `pcl_client.py`) to wrap PCL endpoints from `PCL-API-Document_4.md`.
   - Update `app.py` to initialize the client using existing PACER token flow (`PacerAuthClient` + `pacer_sessions`).
   - Files: `app.py`, `PCL-API-Document_4.md` (reference only), new `pcl_client.py`.

2. **Add database tables for PCL jobs and receipts**
   - Extend inline schema in `app.py` (or move to a models module) with tables for:
     - `pcl_batch_jobs` (job status, report IDs, search criteria, timestamps).
     - `pcl_job_receipts` (costs, item counts, billing metadata).
     - `pcl_case_enrichments` (case ID, enrichment payload metadata, timestamps).
   - Follow existing `_ensure_table_columns()` pattern for additive schema updates.
   - Files: `app.py`.

3. **Admin routes + UI for batch search**
   - Add new admin routes beneath `/admin/federal-data-dashboard` to create, poll, and download PCL batch jobs.
   - Extend `templates/admin_federal_data_get_pacer_data.html` and/or add new templates for the PCL batch UI.
   - Files: `app.py`, `templates/admin_federal_data_get_pacer_data.html`, `templates/admin_federal_data_placeholder.html` (or new templates).

4. **Background job execution + polling strategy**
   - If in-process threads remain acceptable, add a thread runner for batch polling.
   - If Render cron is preferred, implement a cron-safe entry point (e.g., CLI in `scripts/`) to poll and update job status.
   - Files: `app.py`, `scripts/` (new cron runner), `render.yaml` (optional: update cron service entry point).

5. **Optional enrichment workflow**
   - Add routes and UI controls to select cases for enrichment.
   - Store enrichment metadata and results in the new DB tables, linking to existing `case_data_one` records.
   - Files: `app.py`, `templates/admin_case_data_one_list.html` or new enrichment templates, `templates/admin_federal_data_base.html`.

6. **Admin reporting & cost visibility**
   - Add a receipts/cost reporting page backed by `pcl_job_receipts`.
   - Optionally surface cost summaries in the admin dashboard nav.
   - Files: `app.py`, `templates/admin_federal_data_base.html`, new template for receipts.

7. **Documentation & operational guidance**
   - Extend `readme.md` with environment variables for PCL and operational guidance for batch jobs.
   - Add a short runbook for PACER/PCL credential handling and redaction expectations.
   - Files: `readme.md`, `docs/pacer_pcl_pipeline_plan.md` (update as needed).
