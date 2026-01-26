DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'uq_pcl_cases_court_case'
    ) THEN
        ALTER TABLE pcl_cases DROP CONSTRAINT uq_pcl_cases_court_case;
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'uq_pcl_cases_court_case_number_full'
    ) THEN
        ALTER TABLE pcl_cases
            ADD CONSTRAINT uq_pcl_cases_court_case_number_full
            UNIQUE (court_id, case_number_full);
    END IF;
END $$;
