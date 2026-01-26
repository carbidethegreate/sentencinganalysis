BEGIN;

CREATE TABLE IF NOT EXISTS pcl_case_fields (
    id SERIAL PRIMARY KEY,
    case_id INTEGER NOT NULL REFERENCES pcl_cases(id) ON DELETE CASCADE,
    field_name TEXT NOT NULL,
    field_value_text TEXT,
    field_value_json JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_pcl_case_fields_case_field UNIQUE (case_id, field_name)
);

CREATE INDEX IF NOT EXISTS ix_pcl_case_fields_case_id ON pcl_case_fields (case_id);
CREATE INDEX IF NOT EXISTS ix_pcl_case_fields_name ON pcl_case_fields (field_name);
CREATE INDEX IF NOT EXISTS ix_pcl_case_fields_name_value ON pcl_case_fields (field_name, field_value_text);
CREATE INDEX IF NOT EXISTS ix_pcl_case_fields_value_gin ON pcl_case_fields USING GIN (field_value_json);

COMMIT;
