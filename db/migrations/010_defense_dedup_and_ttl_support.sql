-- Issue 16.1
-- Dedup support for external event identifiers in defense_log_event.

ALTER TABLE defense_log_event
    ADD COLUMN IF NOT EXISTS event_external_id VARCHAR(255);

CREATE INDEX IF NOT EXISTS ix_defense_log_event_event_external_id
    ON defense_log_event (event_external_id);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM defense_log_event
        WHERE event_external_id IS NOT NULL
        GROUP BY source_system, event_external_id
        HAVING COUNT(*) > 1
    ) THEN
        EXECUTE 'CREATE UNIQUE INDEX IF NOT EXISTS uq_defense_log_event_source_system_external_id
                 ON defense_log_event (source_system, event_external_id)
                 WHERE event_external_id IS NOT NULL';
    END IF;
END
$$;
