BEGIN;

CREATE TABLE IF NOT EXISTS courts (
    id SERIAL PRIMARY KEY,
    court_id VARCHAR(50) NOT NULL UNIQUE,
    court_name TEXT,
    court_type VARCHAR(40),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_payload JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS court_import_runs (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status VARCHAR(40) NOT NULL,
    source VARCHAR(80),
    records_fetched INTEGER,
    records_inserted INTEGER,
    records_updated INTEGER,
    completed_at TIMESTAMPTZ,
    details JSONB
);

CREATE TABLE IF NOT EXISTS pcl_batch_searches (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    court_id VARCHAR(50) NOT NULL,
    date_filed_from DATE NOT NULL,
    date_filed_to DATE NOT NULL,
    case_types TEXT[] NOT NULL,
    advanced_filters JSONB,
    status VARCHAR(40) NOT NULL,
    created_by VARCHAR(120)
);

ALTER TABLE pcl_batch_segments
    ADD COLUMN IF NOT EXISTS batch_search_id INTEGER,
    ADD COLUMN IF NOT EXISTS segment_from DATE,
    ADD COLUMN IF NOT EXISTS segment_to DATE,
    ADD COLUMN IF NOT EXISTS attempts INTEGER DEFAULT 0,
    ADD COLUMN IF NOT EXISTS last_error TEXT;

CREATE TABLE IF NOT EXISTS pcl_remote_jobs (
    id SERIAL PRIMARY KEY,
    segment_id INTEGER NOT NULL REFERENCES pcl_batch_segments(id),
    remote_job_id VARCHAR(120) NOT NULL,
    submitted_at TIMESTAMPTZ,
    last_polled_at TIMESTAMPTZ,
    remote_status VARCHAR(80),
    deleted_from_pacer_at TIMESTAMPTZ
);

ALTER TABLE pcl_case_result_raw
    ADD COLUMN IF NOT EXISTS ingested_at TIMESTAMPTZ;

ALTER TABLE pcl_cases
    ADD COLUMN IF NOT EXISTS case_id VARCHAR(120),
    ADD COLUMN IF NOT EXISTS effective_date_closed DATE,
    ADD COLUMN IF NOT EXISTS case_link TEXT,
    ADD COLUMN IF NOT EXISTS case_year VARCHAR(10),
    ADD COLUMN IF NOT EXISTS case_office VARCHAR(20),
    ADD COLUMN IF NOT EXISTS source_last_seen_at TIMESTAMPTZ;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'ck_pcl_cases_case_type'
    ) THEN
        ALTER TABLE pcl_cases
            ADD CONSTRAINT ck_pcl_cases_case_type
            CHECK (case_type in ('cr','crim','ncrim','dcrim'));
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS pcl_receipts (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    segment_id INTEGER REFERENCES pcl_batch_segments(id),
    remote_job_id INTEGER REFERENCES pcl_remote_jobs(id),
    billable_pages INTEGER,
    fee INTEGER,
    client_code VARCHAR(120),
    description TEXT,
    report_id VARCHAR(120),
    raw_payload JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_pcl_cases_court_date ON pcl_cases (court_id, date_filed);
CREATE INDEX IF NOT EXISTS ix_pcl_cases_case_type ON pcl_cases (case_type);
CREATE INDEX IF NOT EXISTS ix_pcl_cases_judge_last_name ON pcl_cases (judge_last_name);
CREATE INDEX IF NOT EXISTS ix_pcl_cases_court_case_number_full ON pcl_cases (court_id, case_number_full);

COMMIT;
