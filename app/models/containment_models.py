import datetime
from typing import Any, Optional

from sqlalchemy.dialects.postgresql import JSONB
from sqlmodel import SQLModel, Field, Column, Text


class ContainmentActionAuditBase(SQLModel):
    repository_id: Optional[int] = Field(default=None, index=True, foreign_key="repository.id")
    source_alert_id: Optional[int] = Field(default=None, index=True, foreign_key="threat_alert.id")
    correlation_id: Optional[str] = Field(default=None, index=True, max_length=128)

    action_type: str = Field(index=True, max_length=64)
    target_type: str = Field(index=True, max_length=64)
    target_value: str = Field(index=True, max_length=255)
    reason: str = Field(sa_column=Column(Text))
    requested_by: str = Field(index=True, max_length=120)
    status: str = Field(default="REQUESTED", index=True, max_length=32)
    execution_mode: str = Field(default="STUB", max_length=32)
    provider: str = Field(default="LOCAL_STUB", max_length=64)
    details: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSONB))
    error_message: Optional[str] = Field(default=None, sa_column=Column(Text))


class ContainmentActionAudit(ContainmentActionAuditBase, table=True):
    __tablename__ = "containment_action_audit"
    id: Optional[int] = Field(default=None, primary_key=True)
    requested_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow, index=True, nullable=False)
    executed_at: Optional[datetime.datetime] = Field(default=None, index=True)
    updated_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow, index=True, nullable=False)


class ContainmentActionAuditRead(ContainmentActionAuditBase):
    id: int
    requested_at: datetime.datetime
    executed_at: Optional[datetime.datetime] = None
    updated_at: datetime.datetime


class ContainmentActionStatusUpdate(SQLModel):
    status: str
    error_message: Optional[str] = None


class BaseContainmentRequest(SQLModel):
    repository_id: Optional[int] = None
    source_alert_id: Optional[int] = None
    correlation_id: Optional[str] = None
    reason: str
    requested_by: str
    dry_run: bool = True
    request_metadata: dict[str, Any] = Field(default_factory=dict)


class IsolateNodeRequest(BaseContainmentRequest):
    host_id: str
    network_segment: Optional[str] = None
    quarantine_policy: Optional[str] = None


class BlockIpRequest(BaseContainmentRequest):
    ip_address: str
    direction: str = "BOTH"
    duration_minutes: int = 60
    rule_scope: str = "EDGE_FIREWALL"


class RestoreBackupRequest(BaseContainmentRequest):
    asset_id: str
    backup_snapshot_id: Optional[str] = None
    restore_strategy: str = "LATEST_SAFE"
    validate_hash_before_restore: bool = True


class DeployHoneypotRequest(BaseContainmentRequest):
    decoy_target: str
    honeypot_profile: str = "COWRIE_SSH"
    ttl_minutes: int = 240
    network_zone: Optional[str] = None


class ContainmentActionResponse(SQLModel):
    audit: ContainmentActionAuditRead
    message: str
    next_steps: list[str] = Field(default_factory=list)
