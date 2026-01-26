ALTER TABLE pcl_cases
    ADD COLUMN IF NOT EXISTS last_search_run_id INTEGER,
    ADD COLUMN IF NOT EXISTS last_search_run_at TIMESTAMPTZ;

ALTER TABLE pcl_parties
    ADD COLUMN IF NOT EXISTS last_search_run_id INTEGER,
    ADD COLUMN IF NOT EXISTS last_search_run_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS ix_pcl_cases_last_search_run
    ON pcl_cases (last_search_run_id);

CREATE INDEX IF NOT EXISTS ix_pcl_parties_last_search_run
    ON pcl_parties (last_search_run_id);
