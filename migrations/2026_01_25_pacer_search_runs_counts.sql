ALTER TABLE pacer_search_runs
    ADD COLUMN IF NOT EXISTS cases_inserted INTEGER;

ALTER TABLE pacer_search_runs
    ADD COLUMN IF NOT EXISTS cases_updated INTEGER;

ALTER TABLE pacer_search_runs
    ADD COLUMN IF NOT EXISTS parties_inserted INTEGER;

ALTER TABLE pacer_search_runs
    ADD COLUMN IF NOT EXISTS parties_updated INTEGER;
