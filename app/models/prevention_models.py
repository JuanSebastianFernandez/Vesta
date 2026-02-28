import datetime
import uuid
from typing import Any, Optional
from sqlmodel import SQLModel, Field, Column, Relationship, Text
from sqlalchemy.dialects.postgresql import JSONB
from pgvector.sqlalchemy import VECTOR


#---------------- Repository Models ----------------------
class RepositoryBase(SQLModel):
    url: str = Field(index=True, unique=True)
    commit_hash: Optional[str] = Field(default="main")


class Repository(RepositoryBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    reports: list["Report"] = Relationship(back_populates="repository")

class RepositoryCreate(RepositoryBase):
    pass # Don't need aditional fields

class RepositoryRead(RepositoryBase):
    id: int

# --------------- Report Models ---------------------
class ReportCore(SQLModel):
    file_hash: str = Field(index=True, unique=True, max_length=64)
    file_name: Optional[str] = Field(default=None, index=True, max_length=255)
    language: str = Field(index=True, max_length=20)
    label: Optional[int] = Field(default=None, index=True)
    prediction_probability: Optional[float] = Field(default=None)
    risk_score: Optional[float] = Field(default=None, index=True)
    prediction_source: Optional[str] = Field(default=None, max_length=50)
    amount_findings: int
    antlr_report: list[dict[str, Any]] = Field(sa_column=Column(JSONB))
    antlr_features: dict[str, Any] = Field(sa_column=Column(JSONB))

class ReportBase(ReportCore):
    source_code: str = Field(sa_column=Column(Text))
    codebert_embedding: Optional[list[float]] = Field(default=None, sa_column=Column(VECTOR(768)))

class Report(ReportBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    analysis_date: datetime.datetime = Field(default_factory=datetime.datetime.utcnow, nullable=False, index=True)
    repository_id: Optional[int] = Field(default=None, foreign_key="repository.id")
    repository: Optional[Repository] = Relationship(back_populates="reports")
    
class ReportCreate(ReportBase):
    pass

class ReportRead(ReportCore):
    security_status: Optional[str] = None
    message: Optional[str] = None

# ----------- Mixed models for more complete responses ------------
class ReportReadWithRepository(ReportRead):
    repository: Optional[RepositoryRead] = None

class RepositoryReadWithReports(RepositoryRead):
    reports: list[ReportRead] = []


# --------------- Analysis Job Models ---------------------
class AnalysisJobBase(SQLModel):
    repository_url: str = Field(index=True, max_length=1024)
    repository_name: str = Field(index=True, max_length=255)
    commit_hash: Optional[str] = Field(default="main", max_length=128)
    trigger_source: str = Field(default="MANUAL", max_length=20)
    status: str = Field(default="PENDING", index=True, max_length=20)
    error_message: Optional[str] = Field(default=None, max_length=4000)
    result_summary: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSONB))
    created_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow, nullable=False, index=True)
    started_at: Optional[datetime.datetime] = Field(default=None)
    finished_at: Optional[datetime.datetime] = Field(default=None)


class AnalysisJob(AnalysisJobBase, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True, max_length=36)


class AnalysisJobCreate(SQLModel):
    url: str
    commit_hash: Optional[str] = "main"


class AnalysisJobRead(AnalysisJobBase):
    id: str

