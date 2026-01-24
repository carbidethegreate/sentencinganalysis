BEGIN;

CREATE TABLE IF NOT EXISTS pacer_explore_runs (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by VARCHAR(120),
    mode VARCHAR(20) NOT NULL,
    court_id VARCHAR(50),
    date_from DATE,
    date_to DATE,
    request_params JSONB NOT NULL,
    pages_fetched INTEGER NOT NULL DEFAULT 0,
    receipts JSONB,
    observed_fields JSONB,
    error_summary TEXT
);

CREATE INDEX IF NOT EXISTS ix_pacer_explore_runs_created_at
    ON pacer_explore_runs (created_at);

COMMIT;
