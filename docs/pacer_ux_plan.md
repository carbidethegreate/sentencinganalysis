PACER UX + Data Plan

Status
- Phase 1: Done (Immediate vs Batch UX switch, improved hub entry points).
- Phase 2: Done (Unified search run storage + dedupe indicators).
- Phase 3: Done (Saved searches + run history; sort controls; search reuse; case provenance).
- Phase 4: In progress (Enrichment + expansion actions, dynamic PACER field capture, and case-card UX cleanup).

Latest update
- Removed the automatic criminal-only case-type constraint so civil cases can be saved.
- Added dynamic field capture plan to store every PACER field as a searchable value.
- Added new filters for PACER field name/value on case lists and cards.
- Added a normalized PACER field section to the case detail view.

Current focus
1) Apply the PACER reference-table and case-field migrations in production.
2) Persist all PACER fields (cases + courtCase) into `pcl_case_fields`.
3) Make PACER field search filters reliable on Case Cards and Indexed Cases.
4) Keep PACER run provenance visible on saved cases and cards.
5) Expand enrichment tracking to include completed status + receipts.

Next steps
- Apply the PACER case-field migration in production.
- Confirm `ck_pcl_cases_case_type` is dropped in production to allow all case types.
- Add UI affordances for field search (helpers, chips, or suggestions).
- Add worker wiring for docket enrichment endpoints once available.

Notes
- This plan will be updated as each step is completed.
