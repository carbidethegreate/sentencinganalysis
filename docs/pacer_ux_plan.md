PACER UX + Data Plan

Status
- Phase 1: Done (Immediate vs Batch UX switch, improved hub entry points).
- Phase 2: Done (Unified search run storage + dedupe indicators).
- Phase 3: Done (Saved searches + run history; sort controls; search reuse; case provenance).
- Phase 4: In progress (Enrichment + expansion actions, dynamic PACER field capture, and case-card UX cleanup).

Latest update
- Tightened PACER Explore UI (compact environment/auth details + tab-style mode switch).
- Reworked Docket Enrichment to support filterable batch queueing + clearer admin workflow.
- Added case detail fallback to display parsed PACER fields when normalized fields are missing.
- Fixed SQLAlchemy truthy checks causing Internal Server Errors on case lists and details.
- Wired docket enrichment worker to pull docket reports via PACER case links.

Current focus
1) Validate docket enrichment output and confirm docket text is stored in `pcl_case_fields`.
2) Persist all PACER fields (cases + courtCase) into `pcl_case_fields`.
3) Make PACER field search filters reliable on Case Cards and Indexed Cases.
4) Keep PACER run provenance visible on saved cases and cards.
5) Expand enrichment tracking to include completed status + receipts.

Next steps
- Apply the PACER case-field migration in production.
- Confirm `ck_pcl_cases_case_type` is dropped in production to allow all case types.
- Add UI affordances for field search (helpers, chips, or suggestions).
- Confirm docket report URLs resolve across courts and adjust PACER docket template if needed.

Notes
- This plan will be updated as each step is completed.
