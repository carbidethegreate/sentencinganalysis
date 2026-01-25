CREATE TABLE IF NOT EXISTS pcl_courts (
    pcl_court_id VARCHAR(50) PRIMARY KEY,
    name TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    source TEXT NOT NULL
);
