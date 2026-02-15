BEGIN;

CREATE TABLE IF NOT EXISTS case_entities (
    id SERIAL PRIMARY KEY,
    case_id INTEGER NOT NULL REFERENCES pcl_cases(id) ON DELETE CASCADE,
    entity_type TEXT NOT NULL,
    value TEXT NOT NULL,
    value_normalized TEXT NOT NULL,
    source_field TEXT,
    meta_json JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_case_entities_case_type_value UNIQUE (case_id, entity_type, value_normalized)
);

CREATE INDEX IF NOT EXISTS ix_case_entities_case_id ON case_entities (case_id);
CREATE INDEX IF NOT EXISTS ix_case_entities_type_value ON case_entities (entity_type, value_normalized);
CREATE INDEX IF NOT EXISTS ix_case_entities_value_normalized ON case_entities (value_normalized);

COMMIT;

