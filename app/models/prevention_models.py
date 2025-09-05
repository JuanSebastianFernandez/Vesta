import datetime
from typing import Any, Optional
from sqlmodel import SQLModel, Field, Column, Relationship, Text
from sqlalchemy.dialects.postgresql import JSONB
from pgvector.sqlalchemy import VECTOR


#---------------- Repository Models ----------------------
class RepositoryBase(SQLModel):
    name: str = Field(index=True, unique=True)
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


if __name__ == "__main__":
    # Test for making objects and validate that classes are working well
    from db.sintetic_data import sintetic_data

    # Create a repository Object
    repository = RepositoryCreate(name="GenSQLDatasets", url="https://github.com/JuanSebastianFernandez/GenSQLDatasets")
    # Simulated pass before insert or update db
    # db_repository = Repository.model_validate(repository)     # Tipical way to insert in db
    db_repository = Repository(**repository.model_dump(), id=1)
    # Read repository
    db_repository_read = RepositoryRead.model_validate(db_repository)
    print(f"---------------------- Repository read ---------------\n")
    print(db_repository_read.model_dump())
    print("\n"*3)

    # Reports
    data = sintetic_data[0]
    report = ReportCreate(file_hash="asdf645asdafdf654asfasdasd44564af654asdf654adsf", 
                        source_code=data.get("original_code", ""),
                        language=data.get("language", "Not Language"),
                        label=0,
                        amount_findings = data.get("amount_findings", 0),
                        antlr_report=data.get("static_findings", [{"Report":"Without Report"}]),
                        antlr_features=data.get("antlr_features", {"Features":"Without Features"}),
                        codebert_embedding=data.get("codebert_embedding"))
    
    db_report = Report(**report.model_dump(), id=1, repository = db_repository)
    db_report_read = ReportRead.model_validate(db_report)
    print(f"---------------------- Report read ---------------\n")
    print(db_report_read.model_dump())
    print("\n"*3)


    # Read Repos with their Reports
    db_repository_read_with_reports = RepositoryReadWithReports(**db_repository_read.model_dump(), reports=[db_report_read])
    print(f"---------------------- Repository read with reports ---------------\n") 
    print(db_repository_read_with_reports.model_dump())
    print("\n"*3)

    # Read Reports with their Repos
    db_report_read_with_repository = ReportReadWithRepository(**db_report_read.model_dump(), repository=db_repository_read)
    print(f"---------------------- Report read with repository ---------------\n")
    print(db_report_read_with_repository.model_dump())