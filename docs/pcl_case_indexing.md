# PCL case indexing schema (normalized)

## Tables

- `courts`
  - Stores court metadata sourced from external feeds, including the raw `source_payload` JSON.
- `court_import_runs`
  - Tracks ingestion runs for court metadata (status, counts, timestamps).
- `pcl_batch_searches`
  - Represents a batch search request (court + date range + case types) with optional `advanced_filters` JSON.
- `pcl_batch_segments`
  - Segmented slices of a batch search for PCL paging/limits, including attempt tracking and error state.
- `pcl_remote_jobs`
  - Tracks remote PCL jobs tied to a segment (job ids, submission/poll timestamps, remote status).
- `pcl_case_result_raw`
  - Stores raw PCL payloads (JSON) for each case result, linked to a segment and hashed for dedupe.
- `pcl_cases`
  - Normalized case index for admin search cards (case metadata, parsed year/office, judge last name).
  - Enforces criminal-only case types (`cr`, `crim`, `ncrim`, `dcrim`) via check constraint.
- `pcl_receipts`
  - Captures receipt payloads for billing/cost tracking, tied to a segment or remote job.

## Indexes

- `pcl_cases (court_id, date_filed)`
- `pcl_cases (court_id, case_number_full)`
- `pcl_cases case_type`
- `pcl_cases judge_last_name`

## Notes

- SQLite uses generic JSON storage for development; Postgres uses JSONB/arrays in production.
- For Postgres deployments, see `migrations/2025_03_14_pcl_case_indexing.sql` for the additive DDL.
