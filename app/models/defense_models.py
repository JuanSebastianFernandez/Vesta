import datetime
from typing import Any, Optional

from sqlalchemy.dialects.postgresql import JSONB
from sqlmodel import SQLModel, Field, Column, Text


class DefenseLogEventBase(SQLModel):
    repository_id: Optional[int] = Field(default=None, index=True, foreign_key="repository.id")
    source_system: str = Field(index=True, max_length=120)
    event_external_id: Optional[str] = Field(default=None, index=True, max_length=255)
    source_ip: Optional[str] = Field(default=None, index=True, max_length=64)
    host_id: Optional[str] = Field(default=None, index=True, max_length=255)
    user_id: Optional[str] = Field(default=None, index=True, max_length=255)
    event_type: str = Field(index=True, max_length=80)
    severity: Optional[str] = Field(default=None, max_length=20)
    message: str = Field(sa_column=Column(Text))
    event_time: datetime.datetime = Field(default_factory=datetime.datetime.utcnow, index=True, nullable=False)
    event_context: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSONB))
    raw_payload: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSONB))


class DefenseLogEvent(DefenseLogEventBase, table=True):
    __tablename__ = "defense_log_event"
    id: Optional[int] = Field(default=None, primary_key=True)
    ingested_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow, index=True, nullable=False)


class DefenseLogEventCreate(DefenseLogEventBase):
    pass


class DefenseLogEventRead(DefenseLogEventBase):
    id: int
    ingested_at: datetime.datetime


class ThreatPatternRuleBase(SQLModel):
    code: str = Field(index=True, unique=True, max_length=80)
    name: str = Field(max_length=255)
    description: str = Field(sa_column=Column(Text))
    severity: str = Field(default="MEDIUM", max_length=20)
    weight: float = Field(default=1.0)
    is_active: bool = Field(default=True, index=True)
    window_minutes: int = Field(default=10)
    threshold: int = Field(default=5)
    min_unique_targets: int = Field(default=1)
    extra_params: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSONB))


class ThreatPatternRule(ThreatPatternRuleBase, table=True):
    __tablename__ = "threat_pattern_rule"
    id: Optional[int] = Field(default=None, primary_key=True)
    created_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow, nullable=False, index=True)
    updated_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow, nullable=False, index=True)


class ThreatPatternRuleCreate(ThreatPatternRuleBase):
    pass


class ThreatPatternRuleUpdate(SQLModel):
    name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    weight: Optional[float] = None
    is_active: Optional[bool] = None
    window_minutes: Optional[int] = None
    threshold: Optional[int] = None
    min_unique_targets: Optional[int] = None
    extra_params: Optional[dict[str, Any]] = None


class ThreatPatternRuleRead(ThreatPatternRuleBase):
    id: int
    created_at: datetime.datetime
    updated_at: datetime.datetime


class ThreatAlertBase(SQLModel):
    repository_id: Optional[int] = Field(default=None, index=True, foreign_key="repository.id")
    rule_code: str = Field(index=True, max_length=80, foreign_key="threat_pattern_rule.code")
    source_system: str = Field(index=True, max_length=120)
    source_ip: Optional[str] = Field(default=None, index=True, max_length=64)
    host_id: Optional[str] = Field(default=None, index=True, max_length=255)
    severity: str = Field(default="MEDIUM", max_length=20)
    score: float = Field(default=0.0, index=True)
    confidence: float = Field(default=0.0)
    status: str = Field(default="OPEN", index=True, max_length=20)
    summary: str = Field(sa_column=Column(Text))
    context_window_start: Optional[datetime.datetime] = Field(default=None, index=True)
    context_window_end: Optional[datetime.datetime] = Field(default=None, index=True)
    evidence_count: int = Field(default=0)
    unique_targets: int = Field(default=0)
    evidence: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSONB))


class ThreatAlert(ThreatAlertBase, table=True):
    __tablename__ = "threat_alert"
    id: Optional[int] = Field(default=None, primary_key=True)
    created_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow, nullable=False, index=True)
    updated_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow, nullable=False, index=True)


class ThreatAlertRead(ThreatAlertBase):
    id: int
    created_at: datetime.datetime
    updated_at: datetime.datetime


class ThreatAlertStatusUpdate(SQLModel):
    status: str


class DefenseIngestResponse(SQLModel):
    event: DefenseLogEventRead
    triggered_alerts: list[ThreatAlertRead] = Field(default_factory=list)
    analyzed_rules: int = 0
    action_recommended: str = "NONE"
    duplicate_event: bool = False
    duplicate_of_event_id: Optional[int] = None


class DefenseReanalyzeRequest(SQLModel):
    repository_id: Optional[int] = None
    source_system: Optional[str] = None
    date_from: Optional[datetime.datetime] = None
    date_to: Optional[datetime.datetime] = None
    event_limit: int = Field(default=5000, ge=1, le=50000)
    close_existing_open_alerts: bool = True
    run_ttl_autoclose_before_reanalyze: bool = True


class DefenseReanalyzeResponse(SQLModel):
    events_scanned: int = 0
    events_reanalyzed: int = 0
    rules_evaluated: int = 0
    alerts_triggered_or_updated: int = 0
    alerts_closed_before_reanalyze: int = 0
    alerts_auto_closed_by_ttl: int = 0


class DefenseAutoCloseResponse(SQLModel):
    ttl_minutes: int
    include_critical: bool
    closed_alerts: int
