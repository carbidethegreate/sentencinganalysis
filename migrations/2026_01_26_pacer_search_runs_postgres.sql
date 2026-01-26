CREATE TABLE IF NOT EXISTS pacer_search_runs (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    search_type TEXT NOT NULL,
    search_mode TEXT NOT NULL,
    criteria_json TEXT NOT NULL,
    report_id TEXT,
    report_status TEXT,
    receipt_json TEXT NOT NULL,
    page_info_json TEXT,
    raw_response_json TEXT,
    CONSTRAINT ck_pacer_search_runs_type CHECK (search_type IN ('case', 'party')),
    CONSTRAINT ck_pacer_search_runs_mode CHECK (search_mode IN ('immediate', 'batch'))
);

CREATE INDEX IF NOT EXISTS ix_pacer_search_runs_created_at
    ON pacer_search_runs (created_at);

CREATE TABLE IF NOT EXISTS pcl_parties (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    case_id INTEGER NOT NULL REFERENCES pcl_cases(id),
    last_name TEXT,
    first_name TEXT,
    middle_name TEXT,
    party_type TEXT,
    party_role TEXT,
    party_name TEXT,
    source_last_seen_at TIMESTAMPTZ,
    record_hash TEXT NOT NULL UNIQUE,
    data_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_pcl_parties_case_id
    ON pcl_parties (case_id);
