PACER UX + Data Plan

Status
- Phase 1: Done (Immediate vs Batch UX switch, improved hub entry points).
- Phase 2: Done (Unified search run storage + dedupe indicators).
- Phase 3: Done (Saved searches + run history; sort controls; search reuse; case provenance).
- Phase 4: In progress (Enrichment + expansion actions tied to case status and run provenance).

Latest update
- Added a safe fallback when the saved-search table is not migrated yet to prevent 500 errors.
- Re-read the PACER/PCL PDFs and updated the reference summary to align with available tables.
- Generated reference-table migration from Appendix A/E/F data and wired the UI to prefer PACER tables for courts and case types.
- Added PACER response-code context to PCL API errors.
- Added sortable-field controls to Explore PACER using pacer_sortable_case_fields and pacer_sortable_party_fields.
- Displayed region + sort context in saved searches and run history.
- Stored PACER search run provenance on cases/parties and surfaced it in the case list + detail views.
- Added Expand data actions on Explore results and Indexed Cases, plus enrichment status badges.

Current focus
1) Apply the PACER reference-table migration in production.
2) Leverage PACER/PCL reference tables to tighten validation and improve search UX:
   - Pacer Response Codes: map API status to human-readable errors.
   - Search Regions in Production: limit and validate court region filters.
   - Case Types: drive caseType selects and validation.
   - pacer_courts: source court IDs/labels for filters.
   - pacer_sortable_case_fields / pacer_sortable_party_fields: expose sorting options in the UI.
3) Add case provenance cues:
   - Display last run info on Indexed Cases.
   - Link saved searches to their last run and run counts.
4) Surface sort + region details in run history and saved search summaries.
5) Apply the PACER run provenance migration in production.

Next steps
- Apply the PACER run provenance migration in production.
- Expand enrichment tracking to include completed status + receipts.
- Add worker wiring for docket enrichment endpoints once available.

Notes
- This plan will be updated as each step is completed.
