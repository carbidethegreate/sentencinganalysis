BEGIN;

UPDATE pcl_cases
SET case_number_full = case_number
WHERE case_number_full IS NULL OR BTRIM(case_number_full) = '';

CREATE UNIQUE INDEX IF NOT EXISTS uq_pcl_cases_court_case_id
    ON pcl_cases (court_id, case_id)
    WHERE case_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_pcl_cases_court_case_number_full
    ON pcl_cases (court_id, case_number_full)
    WHERE case_number_full IS NOT NULL;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'uq_pcl_cases_court_case'
    ) THEN
        ALTER TABLE pcl_cases DROP CONSTRAINT uq_pcl_cases_court_case;
    END IF;
END $$;

COMMIT;
