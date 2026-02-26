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

def get_session():
    """
    Data Bases Sessions generate that it's using like dependency.
    It sures that the session always will close.
    """
    with Session(engine) as session:
        yield session
