-- Issue 7: add explicit prediction persistence fields on report table.
ALTER TABLE report
    ADD COLUMN IF NOT EXISTS prediction_probability DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS risk_score DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS prediction_source VARCHAR(50);

CREATE INDEX IF NOT EXISTS ix_report_risk_score ON report (risk_score);
