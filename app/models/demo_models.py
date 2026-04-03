import datetime
from typing import Any, Optional

from sqlmodel import Field, SQLModel


class DemoScenarioRunRequest(SQLModel):
    repository_id: Optional[int] = None
    requested_by: str = "demo.operator"
    auto_contain: bool = True


class DemoRuntimeAsset(SQLModel):
    host_id: str
    container_name: str
    status: str
    image: str
    networks: list[str] = Field(default_factory=list)
    quarantine: bool = False
    honeypot: bool = False
    ports: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)


class DemoRuntimeAssetsResponse(SQLModel):
    enabled: bool
    provider: str
    assets: list[DemoRuntimeAsset] = Field(default_factory=list)
    honeypot_active: bool = False
    honeypot_ttl_minutes: Optional[int] = None
    honeypot_expires_at: Optional[datetime.datetime] = None
    last_actions: list[dict[str, Any]] = Field(default_factory=list)
