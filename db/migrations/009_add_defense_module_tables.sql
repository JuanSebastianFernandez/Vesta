-- Issue 16: Active Defense module persistence
-- Creates tables for:
-- 1) log/event ingestion
-- 2) persisted threat pattern rules
-- 3) generated alerts with contextual evidence

CREATE TABLE IF NOT EXISTS threat_pattern_rule (
    id SERIAL PRIMARY KEY,
    code VARCHAR(80) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
    weight DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    window_minutes INTEGER NOT NULL DEFAULT 10,
    threshold INTEGER NOT NULL DEFAULT 5,
    min_unique_targets INTEGER NOT NULL DEFAULT 1,
    extra_params JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS defense_log_event (
    id SERIAL PRIMARY KEY,
    repository_id INTEGER NULL REFERENCES repository(id),
    source_system VARCHAR(120) NOT NULL,
    event_external_id VARCHAR(255) NULL,
    source_ip VARCHAR(64) NULL,
    host_id VARCHAR(255) NULL,
    user_id VARCHAR(255) NULL,
    event_type VARCHAR(80) NOT NULL,
    severity VARCHAR(20) NULL,
    message TEXT NOT NULL,
    event_time TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
    event_context JSONB NOT NULL DEFAULT '{}'::jsonb,
    raw_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    ingested_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS threat_alert (
    id SERIAL PRIMARY KEY,
    repository_id INTEGER NULL REFERENCES repository(id),
    rule_code VARCHAR(80) NOT NULL REFERENCES threat_pattern_rule(code),
    source_system VARCHAR(120) NOT NULL,
    source_ip VARCHAR(64) NULL,
    host_id VARCHAR(255) NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
    score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    status VARCHAR(20) NOT NULL DEFAULT 'OPEN',
    summary TEXT NOT NULL,
    context_window_start TIMESTAMP WITHOUT TIME ZONE NULL,
    context_window_end TIMESTAMP WITHOUT TIME ZONE NULL,
    evidence_count INTEGER NOT NULL DEFAULT 0,
    unique_targets INTEGER NOT NULL DEFAULT 0,
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_defense_log_event_repository_id ON defense_log_event (repository_id);
CREATE INDEX IF NOT EXISTS ix_defense_log_event_source_system ON defense_log_event (source_system);
CREATE INDEX IF NOT EXISTS ix_defense_log_event_event_external_id ON defense_log_event (event_external_id);
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
CREATE INDEX IF NOT EXISTS ix_defense_log_event_source_ip ON defense_log_event (source_ip);
CREATE INDEX IF NOT EXISTS ix_defense_log_event_host_id ON defense_log_event (host_id);
CREATE INDEX IF NOT EXISTS ix_defense_log_event_user_id ON defense_log_event (user_id);
CREATE INDEX IF NOT EXISTS ix_defense_log_event_event_type ON defense_log_event (event_type);
CREATE INDEX IF NOT EXISTS ix_defense_log_event_event_time ON defense_log_event (event_time);

CREATE INDEX IF NOT EXISTS ix_threat_pattern_rule_is_active ON threat_pattern_rule (is_active);

CREATE INDEX IF NOT EXISTS ix_threat_alert_repository_id ON threat_alert (repository_id);
CREATE INDEX IF NOT EXISTS ix_threat_alert_rule_code ON threat_alert (rule_code);
CREATE INDEX IF NOT EXISTS ix_threat_alert_source_system ON threat_alert (source_system);
CREATE INDEX IF NOT EXISTS ix_threat_alert_source_ip ON threat_alert (source_ip);
CREATE INDEX IF NOT EXISTS ix_threat_alert_host_id ON threat_alert (host_id);
CREATE INDEX IF NOT EXISTS ix_threat_alert_status ON threat_alert (status);
CREATE INDEX IF NOT EXISTS ix_threat_alert_score ON threat_alert (score);
CREATE INDEX IF NOT EXISTS ix_threat_alert_created_at ON threat_alert (created_at);
