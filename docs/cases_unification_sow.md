# Scope of Work: Unify Admin "Cases" Surfaces

Date: 2026-02-15

## 1) Project Summary
The admin UI currently exposes multiple case-list destinations that overlap in purpose, which makes it hard for attorney users (and even admins) to know where to start. This work consolidates those surfaces into one canonical "Cases" destination, keeps all existing functionality and data intact, and preserves backwards compatibility via safe redirects.

## 2) Personas And Primary Workflow

Primary persona: Attorney (default browsing and decision-making).

Secondary persona: Admin/Ops (triage, bulk actions, monitoring).

Primary workflow (attorney-first):
1. Go to `Federal Data Dashboard -> Cases`.
2. Search/filter to find a case quickly.
3. Open the case detail.
4. Queue/pull the docket when needed.

Secondary workflow (ops):
1. Go to `Federal Data Dashboard -> Cases`.
2. Switch to Operations view.
3. Use advanced filters, bulk actions, saved searches, and run history.

## 3) In-Scope Deliverables
- One canonical admin destination: `GET /admin/federal-data-dashboard/cases`.
- Clear labeling of data sources:
  - PACER indexed cases (PCL-backed).
  - Imported cases (legacy upload dataset).
- Attorney-friendly default view for PACER cases (card view).
- Advanced ops tooling available without removing anything (operations view).
- Backwards compatible redirects for legacy entry points:
  - `/admin/federal-data-dashboard/case-cards`
  - `/admin/pcl/cases`
  - `/admin/case-data-one`
- Documentation explaining "why these existed" and the new canonical path.
- A minimal smoke-test script to verify routes/redirects without adding new test dependencies.

## 4) Out Of Scope
- Schema merges between `pcl_cases` and `case_data_one`.
- Dropping tables or removing data.
- Changing PACER/PCL ingestion logic, throttling behavior, or worker concurrency policies.
- Large visual redesign of the entire dashboard.
- Adding new user roles/permissions beyond existing admin gating (unless requested later).

## 5) UX Decisions
- Canonical name: **Cases**
- Canonical URL: `/admin/federal-data-dashboard/cases`
- Default experience:
  - PACER cases (indexed) + card view.
- Progressive disclosure:
  - Operations view is available as a mode switch for bulk triage and admin-only workflows.
  - Imported cases are explicitly marked as legacy and explained as manually uploaded (not PACER-synced).
- Navigation cleanup:
  - Federal Data Dashboard subnav contains one entry for case browsing: **Cases**.
  - The legacy import entry is still reachable as "Import Case Data (Legacy)" in the admin top nav and via the Imported tab inside Cases.

## 6) Technical Plan

Routes (canonical + compatibility):
- Canonical:
  - `GET /admin/federal-data-dashboard/cases`
    - `source=pacer` (default)
      - `view=cards` (default)
      - `view=ops`
    - `source=imported`
- Redirects (back-compat):
  - `GET /admin/federal-data-dashboard/case-cards` -> canonical (`source=pacer&view=cards`)
  - `GET /admin/pcl/cases` -> canonical (`source=pacer&view=ops`)
  - `GET /admin/case-data-one` -> canonical (`source=imported`)

Templates:
- Canonical wrapper:
  - `templates/admin_cases.html`
- Partial views (to avoid code duplication):
  - `templates/partials/pcl_case_cards_view.html` (PACER cards)
  - `templates/partials/pcl_cases_view.html` (PACER ops)
  - `templates/partials/case_data_one_view.html` (Imported legacy view)

Data access:
- PACER indexed dataset:
  - `pcl_queries.py:list_case_cards()`
  - `pcl_queries.py:list_cases()`
- Imported dataset:
  - `case_data_one` table defined in `app.py`
  - JSON endpoint remains: `GET /admin/case-data-one/data`
  - Import status polling remains: `GET /admin/case-data-one/import-status`
  - Upload remains: `GET/POST /admin/case-data-one/upload`

Non-goals:
- No changes to downstream case detail routes (`/admin/pcl/cases/<id>`) or docket enrichment endpoints.

## 7) Data Considerations
- `pcl_cases` and `case_data_one` are different datasets with different schemas and provenance.
- UI consolidation is safe without forcing a schema merge.
- If cross-linking/matching becomes a requirement later:
  - It needs explicit match rules (court + case number normalization) and should be shipped as a separate, testable phase.

## 8) Testing Plan
Automated (no pytest required):
- `scripts/smoke_cases_routes.py`
  - Confirms canonical routes return `200`.
  - Confirms legacy routes return `302` redirects to canonical.

Manual regression checklist:
- Verify `Federal Data Dashboard -> Cases` is the only case-list nav entry.
- Confirm PACER card view filters and pagination work.
- Confirm operations view filters/bulk tools still load and submit correctly.
- Confirm imported cases view loads records (JS fetch works) and filters paginate.
- Confirm upload page is reachable and status polling works.

## 9) Rollout Plan
1. Deploy to staging.
2. Verify smoke checks and manual checklist on staging.
3. Deploy to production.

Rollback:
- Revert the commits that introduced the canonical route and redirects.
- Navigation changes can be reverted independently if needed.

## 10) Acceptance Criteria
- There is exactly one obvious place to browse cases: `Federal Data Dashboard -> Cases`.
- Old URLs still work (redirect or remain reachable) and do not 404.
- No loss of functionality:
  - PACER cases can still be filtered and opened.
  - Ops users can still do bulk workflows.
  - Imported dataset upload and browsing still work.
- Smoke checks pass in CI/local: `python3 scripts/smoke_cases_routes.py`.

## 11) Risks And Mitigations
- Risk: Users still confuse data sources (PACER vs imported).
  - Mitigation: Explicit labels + a short note on the Cases page; keep imported labeled "legacy".
- Risk: Redirects break deep links in internal tools.
  - Mitigation: Redirect targets preserve query params where applicable and keep downstream endpoints unchanged.
- Risk: Performance regression when browsing large case sets.
  - Mitigation: Preserve existing query paths; do not add new joins to the default card view.

