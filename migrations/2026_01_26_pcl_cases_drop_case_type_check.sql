DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'ck_pcl_cases_case_type'
    ) THEN
        ALTER TABLE pcl_cases DROP CONSTRAINT ck_pcl_cases_case_type;
    END IF;
END $$;
