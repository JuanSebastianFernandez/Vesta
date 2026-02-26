-- Optional hardening migration:
-- If your DB has report.label as NOT NULL, allow NULL to support tri-state logic.
ALTER TABLE report
    ALTER COLUMN label DROP NOT NULL;
