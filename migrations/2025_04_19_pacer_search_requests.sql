CREATE TABLE IF NOT EXISTS pacer_search_requests (
    id INTEGER PRIMARY KEY,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    search_type TEXT NOT NULL,
    search_mode TEXT NOT NULL,
    criteria_json TEXT NOT NULL,
    report_id TEXT,
    report_status TEXT,
    report_meta_json TEXT,
    CONSTRAINT ck_pacer_search_requests_type CHECK (search_type IN ('case', 'party')),
    CONSTRAINT ck_pacer_search_requests_mode CHECK (search_mode IN ('immediate', 'batch'))
);

CREATE INDEX IF NOT EXISTS ix_pacer_search_requests_created_at
    ON pacer_search_requests (created_at);
