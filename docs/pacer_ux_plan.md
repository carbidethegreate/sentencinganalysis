PACER UX + Data Plan

Status
- Phase 1: Done (Immediate vs Batch UX switch, improved hub entry points).
- Phase 2: Done (Unified search run storage + dedupe indicators).
- Phase 3: Done (Saved searches + run history panels; reusable search runs).
- Phase 4: Next (Enrichment + expansion actions tied to case status and run provenance).

Latest update
- Added a safe fallback when the saved-search table is not migrated yet to prevent 500 errors.
- Re-read the PACER/PCL PDFs and updated the reference summary to align with available tables.

Current focus
1) Stabilize saved-search loading to avoid 500s when the new table is not yet migrated.
2) Leverage PACER/PCL reference tables to tighten validation and improve search UX:
   - Pacer Response Codes: map API status to human-readable errors.
   - Search Regions in Production: limit and validate court region filters.
   - Case Types: drive caseType selects and validation.
   - pacer_courts: source court IDs/labels for filters.
   - pacer_sortable_case_fields / pacer_sortable_party_fields: expose sorting options in the UI.
3) Add case provenance cues:
   - Display last run info on Indexed Cases.
   - Link saved searches to their last run and run counts.

Next steps
- Apply the saved search migration in production.
- Wire table-backed select lists and validation for case types, courts, regions, and sortable fields.
- Expand run history details and link cases back to the originating run.
- Add enrichment actions from results and case detail pages.

Notes
- This plan will be updated as each step is completed.
