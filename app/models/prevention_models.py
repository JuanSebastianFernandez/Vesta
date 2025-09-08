import datetime
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

