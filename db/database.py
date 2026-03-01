from sqlmodel import SQLModel, create_engine, Session
from sqlalchemy import text
from app.core.config import settings


engine = create_engine(settings.URL_DATABASE)

def create_db_and_tables():
    """
    Create the database and tables if they do not exist.
    """
    SQLModel.metadata.create_all(engine)
    _run_schema_patches()


def _run_schema_patches():
    """
    Apply lightweight idempotent schema patches for existing databases.
    This avoids runtime errors when the code model evolves but DB tables already exist.
    """
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                ALTER TABLE report
                    ADD COLUMN IF NOT EXISTS prediction_probability DOUBLE PRECISION,
                    ADD COLUMN IF NOT EXISTS risk_score DOUBLE PRECISION,
                    ADD COLUMN IF NOT EXISTS prediction_source VARCHAR(50);
                """
            )
        )
        conn.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_report_risk_score ON report (risk_score);"
            )
        )
        conn.execute(
            text(
                "ALTER TABLE report ALTER COLUMN label DROP NOT NULL;"
            )
        )
        conn.execute(
            text(
                """
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
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS defense_log_event (
                    id SERIAL PRIMARY KEY,
                    repository_id INTEGER NULL REFERENCES repository(id),
                    source_system VARCHAR(120) NOT NULL,
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
                """
            )
        )
        conn.execute(
            text(
                """
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
                """
            )
        )
        conn.execute(
            text("CREATE INDEX IF NOT EXISTS ix_defense_log_event_repository_id ON defense_log_event (repository_id);")
        )
        conn.execute(
            text("CREATE INDEX IF NOT EXISTS ix_defense_log_event_source_system ON defense_log_event (source_system);")
        )
        conn.execute(
            text("CREATE INDEX IF NOT EXISTS ix_defense_log_event_source_ip ON defense_log_event (source_ip);")
        )
        conn.execute(
            text("CREATE INDEX IF NOT EXISTS ix_defense_log_event_host_id ON defense_log_event (host_id);")
        )
        conn.execute(
            text("CREATE INDEX IF NOT EXISTS ix_defense_log_event_user_id ON defense_log_event (user_id);")
        )
        conn.execute(
            text("CREATE INDEX IF NOT EXISTS ix_defense_log_event_event_type ON defense_log_event (event_type);")
        )
        conn.execute(
            text("CREATE INDEX IF NOT EXISTS ix_defense_log_event_event_time ON defense_log_event (event_time);")
        )
        conn.execute(
            text("CREATE INDEX IF NOT EXISTS ix_threat_pattern_rule_is_active ON threat_pattern_rule (is_active);")
        )
        conn.execute(
            text("CREATE INDEX IF NOT EXISTS ix_threat_alert_repository_id ON threat_alert (repository_id);")
        )
        conn.execute(
            text("CREATE INDEX IF NOT EXISTS ix_threat_alert_rule_code ON threat_alert (rule_code);")
        )
        conn.execute(
            text("CREATE INDEX IF NOT EXISTS ix_threat_alert_source_system ON threat_alert (source_system);")
        )
        conn.execute(
            text("CREATE INDEX IF NOT EXISTS ix_threat_alert_source_ip ON threat_alert (source_ip);")
        )
        conn.execute(
            text("CREATE INDEX IF NOT EXISTS ix_threat_alert_host_id ON threat_alert (host_id);")
        )
        conn.execute(
            text("CREATE INDEX IF NOT EXISTS ix_threat_alert_status ON threat_alert (status);")
        )
        conn.execute(
            text("CREATE INDEX IF NOT EXISTS ix_threat_alert_score ON threat_alert (score);")
        )
        conn.execute(
            text("CREATE INDEX IF NOT EXISTS ix_threat_alert_created_at ON threat_alert (created_at);")
        )

def get_session():
    """
    Data Bases Sessions generate that it's using like dependency.
    It sures that the session always will close.
    """
    with Session(engine) as session:
        yield session
