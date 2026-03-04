-- Issue 18
-- Containment module audit log table (stub actions with who/when/why traceability).

CREATE TABLE IF NOT EXISTS containment_action_audit (
    id SERIAL PRIMARY KEY,
    repository_id INTEGER NULL REFERENCES repository(id),
    source_alert_id INTEGER NULL REFERENCES threat_alert(id),
    correlation_id VARCHAR(128) NULL,
    action_type VARCHAR(64) NOT NULL,
    target_type VARCHAR(64) NOT NULL,
    target_value VARCHAR(255) NOT NULL,
    reason TEXT NOT NULL,
    requested_by VARCHAR(120) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'REQUESTED',
    execution_mode VARCHAR(32) NOT NULL DEFAULT 'STUB',
    provider VARCHAR(64) NOT NULL DEFAULT 'LOCAL_STUB',
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    error_message TEXT NULL,
    requested_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
    executed_at TIMESTAMP WITHOUT TIME ZONE NULL,
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_containment_action_audit_repository_id ON containment_action_audit (repository_id);
CREATE INDEX IF NOT EXISTS ix_containment_action_audit_source_alert_id ON containment_action_audit (source_alert_id);
CREATE INDEX IF NOT EXISTS ix_containment_action_audit_correlation_id ON containment_action_audit (correlation_id);
CREATE INDEX IF NOT EXISTS ix_containment_action_audit_action_type ON containment_action_audit (action_type);
CREATE INDEX IF NOT EXISTS ix_containment_action_audit_target_type ON containment_action_audit (target_type);
CREATE INDEX IF NOT EXISTS ix_containment_action_audit_target_value ON containment_action_audit (target_value);
CREATE INDEX IF NOT EXISTS ix_containment_action_audit_status ON containment_action_audit (status);
CREATE INDEX IF NOT EXISTS ix_containment_action_audit_requested_by ON containment_action_audit (requested_by);
CREATE INDEX IF NOT EXISTS ix_containment_action_audit_requested_at ON containment_action_audit (requested_at);
CREATE INDEX IF NOT EXISTS ix_containment_action_audit_executed_at ON containment_action_audit (executed_at);
CREATE INDEX IF NOT EXISTS ix_containment_action_audit_updated_at ON containment_action_audit (updated_at);
