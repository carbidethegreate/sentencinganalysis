# Case Surfaces Audit (Admin)

Date: 2026-02-14

This document explains why the admin UI currently has three different "case" pages, what each one does, and where the overlap/confusion comes from. It is grounded in the code in this repo (routes, templates, and query functions).

## TL;DR (What Each Page Is For)

There are two different datasets and three different UIs:

- Dataset A (PACER/PCL indexed cases): `pcl_cases` (+ `pcl_case_fields`, `pcl_batch_segments`, `docket_enrichment_jobs`, `sentencing_events`)
- Dataset B (uploaded "Case Data One" records): `case_data_one` (legacy upload/import feature)

Pages:

1. **Case Cards** (`GET /admin/federal-data-dashboard/case-cards`)
   - A lightweight card-grid view of Dataset A intended for browsing saved PACER/PCL cases with a simple filter form and quick actions.
2. **Indexed Cases** (`GET /admin/pcl/cases`)
   - An operations-heavy view of Dataset A intended for triage: advanced filters, bulk actions, provenance, saved search presets, and run history.
3. **Case Reports** (`GET /admin/case-data-one`)
   - A separate card-grid view of Dataset B, populated by admin uploads (`/admin/case-data-one/upload`) and served via a JSON data endpoint (`/admin/case-data-one/data`).

User confusion is expected because:

- "Case Cards" and "Indexed Cases" are two different UIs over the same dataset (`pcl_cases`).
- "Case Reports" is a different dataset entirely (`case_data_one`), but it is presented in the same top-level admin navigation, so it reads like "another way to view cases" instead of "a legacy uploaded dataset."

## Surface Inventory (Endpoints, Templates, Data Sources)

### 1) Case Cards

- URL
  - Prod: `https://courtdatapro.com/admin/federal-data-dashboard/case-cards`
  - Route: `GET /admin/federal-data-dashboard/case-cards`
  - Handler: `admin_federal_data_dashboard_case_cards()` in `app.py`
- Template
  - `templates/admin_federal_data_case_cards.html`
- Primary data source
  - Query: `list_case_cards(engine, pcl_tables, filters, page=..., page_size=...)` in `pcl_queries.py`
  - Tables: `pcl_cases`, optional `docket_enrichment_jobs`, optional `sentencing_events`, optional `pcl_case_fields` (for field filtering)
- UX purpose (current)
  - "Saved PACER results" card grid with simple filters.
  - Per-card actions:
    - Queue docket enrichment (POST to `/admin/pcl/cases/<id>/docket-enrichment/queue`)
    - "View details" (GET `/admin/pcl/cases/<id>`)
- What it does NOT do
  - No bulk selection or bulk docket-queue actions.
  - No saved-search presets or recent run history.
  - No segment/provenance visibility (monthly segments, last segment status).

- Supported query params (from `pcl_queries.py:parse_filters()`)
  - `court_id`: exact court id (lowercased).
  - `case_type`: exact case type (lowercased).
  - `date_filed_from`, `date_filed_to`: filed date window (swaps if reversed).
  - `judge_last_name`: exact match on judge last name (case-insensitive).
  - `q`: substring match over case number and titles.
  - `field_name` + `field_value`: existence filter against `pcl_case_fields` (text or JSON).
  - `page`, `page_size`: pagination.

### 2) Indexed Cases

- URL
  - Prod: `https://courtdatapro.com/admin/pcl/cases`
  - Route: `GET /admin/pcl/cases`
  - Handler: `admin_pcl_cases()` in `app.py`
- Template
  - `templates/admin_pcl_cases.html`
- Primary data source
  - Query: `list_cases(engine, pcl_tables, filters, page=..., page_size=...)` in `pcl_queries.py`
  - Tables: `pcl_cases`, `pcl_batch_segments`, optional `docket_enrichment_jobs`, optional `sentencing_events`, optional `pcl_case_fields` (for field filtering)
  - Extra sidebar data:
    - Saved PACER search presets: `_load_pacer_saved_searches(limit=6)` in `app.py`
    - Recent PACER runs: `_load_pacer_search_runs(limit=6)` in `app.py`
- UX purpose (current)
  - "Case Operations" and triage:
    - Advanced filter blocks (basics, date window, field contains, status flags)
    - Bulk selection + bulk queue docket enrichment
    - Saved searches and run history for operational context
    - Per-case quick actions (queue docket, copy number, view case)
  - Includes additional provenance data not shown on Case Cards:
    - `pcl_batch_segments` status/window data via `pcl_cases.last_segment_id`
- What it does NOT do
  - It is not opinionated about "attorney-friendly" card content; it is an admin ops surface.

- Supported query params
  - Same as Case Cards, plus these status flags (also parsed by `parse_filters()`):
    - `indexed_only=1`: only cases with a `record_hash` (roughly "saved/indexed").
    - `enriched_only=1`: only cases with docket fields present (or enrichment jobs, depending on table availability).
    - `sentencing_only=1`: only cases with sentencing events present (if `sentencing_events` table exists).

### 3) Case Reports (Case Data One)

- URL
  - Prod: `https://courtdatapro.com/admin/case-data-one`
  - Route: `GET /admin/case-data-one`
  - Handler: `admin_case_data_one_list()` in `app.py`
- Related endpoints
  - Upload UI: `GET /admin/case-data-one/upload` (template `templates/admin_case_data_one_upload.html`)
  - Upload handler: `POST /admin/case-data-one/upload` (background thread import)
  - Data API: `GET /admin/case-data-one/data` (JSON, paginated)
  - Import status: `GET /admin/case-data-one/import-status` (JSON)
  - Error helpers:
    - `POST /admin/case-data-one/error-prompt` (calls OpenAI API to draft a "fix prompt" from import errors)
    - `GET /admin/case-data-one/error-report` (downloads a text error report)
- Template
  - `templates/admin_case_data_one_list.html`
- Primary data source
  - Table: `case_data_one` defined in `app.py` (inline `sqlalchemy.Table`)
  - Client-side rendering:
    - Page loads an empty grid; JS fetches from `/admin/case-data-one/data` and renders cards.
- UX purpose (current)
  - Browse an uploaded dataset (legacy/parallel pipeline) in a card view.
- Key note
  - This dataset is not the same as `pcl_cases` and is not populated by PACER/PCL indexing workflows. It is populated by manual admin uploads.

- Supported query params (Case Data One list/data)
  - Page UI: `GET /admin/case-data-one` (server-rendered shell; JS drives fetching).
  - Data API: `GET /admin/case-data-one/data`
    - `page` (default 1)
    - `per_page` (default 12, max 100)
    - `search` (full-text-ish; Postgres uses tsvector, SQLite uses LIKE)
    - `case_type` (matches `cs_type_normalized`)
    - `party_role` (matches `party_role_normalized`)
    - `party_type` (matches `party_type_normalized`)
    - `case_year` (matches `cs_case_year`)
  - Upload: `POST /admin/case-data-one/upload`
    - Accepts `.txt` or `.csv`, but parses as pipe-delimited (`|`) via `csv.reader(..., delimiter='|')`.

## Why These Exist (Probable Intent) and What They Are Today

### Case Cards vs Indexed Cases

Both are views over `pcl_cases`:

- "Case Cards" looks like it was meant as a simple "browse saved cases" view.
- "Indexed Cases" was built as the operational workbench once ingestion/enrichment/triage became a first-class workflow.

Right now, they overlap heavily in user outcomes:

- Find a case
- Check enrichment/sentencing status
- Queue docket enrichment
- Open the case detail page

The difference is mainly UI density and power-user tooling (bulk actions, saved searches, provenance).

### Case Reports (Case Data One) is a Different System

The `case_data_one` upload/import system predates (or is parallel to) the PCL indexing system:

- It has its own upload UI, import status polling, and error reporting.
- It has a separate schema that does not match `pcl_cases`.
- It is surfaced in the same admin navigation as the Federal Data Dashboard, which makes it read like "another case listing" rather than "legacy uploaded case dataset."

## Verification Notes (What the Code Confirms)

- Both Case Cards and Indexed Cases read from `pcl_cases` and compute enrichment status from `docket_enrichment_jobs`.
  - `pcl_queries.py:list_case_cards()` and `pcl_queries.py:list_cases()`
- Indexed Cases includes extra provenance columns from `pcl_batch_segments` (`segment_status`, `segment_date_from`, etc.).
  - `pcl_queries.py:list_cases()` joins `pcl_batch_segments` on `pcl_cases.last_segment_id`
- Case Reports reads from `case_data_one` and is not joined to `pcl_cases` anywhere in the current UI.
  - `app.py` defines `case_data_one` and serves `/admin/case-data-one/data`
  - `templates/admin_case_data_one_list.html` fetches JSON and renders cards client-side

## The Problem Statement (What Users Experience)

1. Multiple "case list" destinations with overlapping naming:
   - "Indexed Cases" and "Case Cards" are both "cases from PACER" to a non-technical user.
2. Mixed information architecture:
   - "Case Reports" sits in the top admin nav, while "Case Cards" sits inside the Federal Data Dashboard subnav.
   - The UI does not explain that Case Reports is a separate imported dataset.
3. Inconsistent interaction models:
   - Server-rendered filter+paginate (Case Cards / Indexed Cases) vs client-rendered fetch+cards (Case Reports).
4. Attorney expectations mismatch:
   - Attorneys typically want one canonical place to:
     - Find cases
     - See the most important metadata quickly
     - See docket/enrichment state clearly
     - Open the docket and key documents
     - Track notes/summaries
   - They do not want to decide between three similarly named case pages.

## Recommended North-Star (One Canonical "Cases" Surface)

Goal: one canonical "Cases" destination, with clear modes instead of separate pages.

Suggested approach (lowest risk to highest clarity):

1. Create **one** primary route and nav entry (name TBD):
   - Example: `Cases` (recommended) or `Case Cards`
2. Within that single surface, provide:
   - A "Card view" (attorney-friendly summary, minimal controls, strong defaults)
   - An "Operations view" (advanced filters, bulk actions, provenance panels)
3. Treat `case_data_one` as:
   - Either a third mode/tab: "Imported (Legacy)" with explicit labeling, or
   - An admin-only tool removed from primary navigation (still accessible), if no longer needed.
4. Preserve backwards compatibility:
   - Keep existing endpoints working (or 302 redirect to the new canonical route).

## Data Model Reality Check (So We Do Not Lose Functionality)

To consolidate without breaking anything, we must preserve three distinct feature groups:

- A) PACER/PCL ingestion and indexing
  - `pcl_cases`, `pcl_batch_segments`, `pacer_search_runs`, `pacer_saved_searches`
- B) Enrichment workflows
  - `docket_enrichment_jobs`, receipts, docket fields in `pcl_case_fields`
- C) Legacy uploads (if still required)
  - `case_data_one` + upload/import-status/error flows

Consolidation should not force a premature schema merge. UI consolidation can happen first.

## Proposed Implementation Plan (UI Consolidation First)

Phase 1 (UI clarity, minimal risk):

- Add a single "Cases" entry point.
- Move or hide duplicate nav entries.
- Add explicit copy that explains:
  - What dataset you are viewing (PACER indexed vs imported legacy)
  - What actions are available here
- Keep existing endpoints working (ideally redirect with a notice).

Phase 2 (unified cards with optional data bridging):

- Optional: allow linking/matching between `case_data_one` and `pcl_cases` when possible.
  - This requires defining match keys (court + case number, etc.).
  - Do not assume it is safe until verified with real data.

## Open Questions (Need Product Answers Before Deeper Changes)

1. Is `case_data_one` still required for the business, or is it legacy that can be de-emphasized?
2. Who is the primary user for the unified page (attorney vs admin ops)?
3. Do we need roles/permissions (attorney vs admin) to hide ops-only controls?
4. What is the canonical "case" identifier for cross-dataset matching?

## Implementation Status (This Repo)

As of 2026-02-14, this repo now provides a single canonical entry point:

- Canonical: `GET /admin/federal-data-dashboard/cases`
  - `source=pacer` (default)
    - `view=cards` (default): simplified card view (former "Case Cards")
    - `view=ops`: operations view (former "Indexed Cases")
  - `source=imported`: legacy imported cards (former "Case Reports / Case Data One")

Backwards-compatible redirects are in place:

- `/admin/federal-data-dashboard/case-cards` -> `/admin/federal-data-dashboard/cases?source=pacer&view=cards`
- `/admin/pcl/cases` -> `/admin/federal-data-dashboard/cases?source=pacer&view=ops`
- `/admin/case-data-one` -> `/admin/federal-data-dashboard/cases?source=imported`

Navigation changes:

- Federal Data Dashboard subnav now has one "Cases" entry (instead of "Indexed Cases" + "Case Cards").
- Top admin nav no longer shows "Case Reports"; it keeps a single legacy import link: "Import Case Data (Legacy)".
