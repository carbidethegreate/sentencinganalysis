CREATE TABLE IF NOT EXISTS pacer_saved_searches (
  id SERIAL PRIMARY KEY,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  label TEXT NOT NULL,
  search_type VARCHAR(20) NOT NULL,
  search_mode VARCHAR(20) NOT NULL,
  criteria_json TEXT NOT NULL,
  schedule VARCHAR(40),
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_by VARCHAR(120),
  last_run_at TIMESTAMPTZ,
  run_count INTEGER NOT NULL DEFAULT 0,
  CONSTRAINT ck_pacer_saved_searches_type CHECK (search_type IN ('case', 'party')),
  CONSTRAINT ck_pacer_saved_searches_mode CHECK (search_mode IN ('immediate', 'batch'))
);

CREATE INDEX IF NOT EXISTS ix_pacer_saved_searches_created_at
  ON pacer_saved_searches (created_at);
