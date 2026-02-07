CREATE TABLE IF NOT EXISTS docket_document_jobs (
  id SERIAL PRIMARY KEY,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  case_id INTEGER NOT NULL REFERENCES pcl_cases(id),
  status TEXT NOT NULL DEFAULT 'queued',
  documents_total INTEGER,
  documents_downloaded INTEGER,
  last_error TEXT,
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS ix_docket_document_jobs_case_id ON docket_document_jobs(case_id);
CREATE INDEX IF NOT EXISTS ix_docket_document_jobs_status ON docket_document_jobs(status);

CREATE TABLE IF NOT EXISTS docket_document_items (
  id SERIAL PRIMARY KEY,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  job_id INTEGER NOT NULL REFERENCES docket_document_jobs(id),
  document_number TEXT,
  description TEXT,
  source_url TEXT NOT NULL,
  request_method TEXT NOT NULL DEFAULT 'GET',
  request_payload_json TEXT,
  status TEXT NOT NULL DEFAULT 'queued',
  file_path TEXT,
  content_type TEXT,
  bytes INTEGER,
  downloaded_at TIMESTAMPTZ,
  error TEXT
);

CREATE INDEX IF NOT EXISTS ix_docket_document_items_job_id ON docket_document_items(job_id);
CREATE INDEX IF NOT EXISTS ix_docket_document_items_status ON docket_document_items(status);
