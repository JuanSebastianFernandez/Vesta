import datetime
from typing import Any, Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlmodel import Session, select
from sqlalchemy import desc, func

from app.models.defense_models import (
    DefenseLogEvent,
    DefenseLogEventCreate,
    DefenseLogEventRead,
    DefenseIngestResponse,
    ThreatAlert,
    ThreatAlertRead,
    ThreatAlertStatusUpdate,
    ThreatPatternRule,
    ThreatPatternRuleRead,
    ThreatPatternRuleUpdate,
)
from app.services.network_analyzer_service import NetworkAnalyzerService
from app.utilities.logger import logger
from db.database import get_session


router = APIRouter(
    prefix="/defense",
    tags=["Active Defense Module"],
)

SessionDep = Annotated[Session, Depends(get_session)]


def _service(session: SessionDep) -> NetworkAnalyzerService:
    return NetworkAnalyzerService(session=session)


@router.get("/")
async def defense_root() -> dict[str, Any]:
    return {"message": "Active Defense Module is available."}


@router.post(
    "/events",
    status_code=status.HTTP_201_CREATED,
    summary="Ingest one network/security log event and run behavior analysis",
    response_model=DefenseIngestResponse,
)
async def ingest_defense_event(
    payload: DefenseLogEventCreate,
    session: SessionDep,
    auto_analyze: bool = Query(default=True),
):
    service = _service(session)
    response = service.ingest_event(payload=payload, auto_analyze=auto_analyze)
    return response


@router.post(
    "/events/batch",
    status_code=status.HTTP_201_CREATED,
    summary="Ingest a batch of log events and run behavior analysis",
)
async def ingest_defense_events_batch(
    payloads: list[DefenseLogEventCreate],
    session: SessionDep,
    auto_analyze: bool = Query(default=True),
) -> dict[str, Any]:
    service = _service(session)
    responses = service.ingest_events_batch(payloads=payloads, auto_analyze=auto_analyze)
    return {
        "ingested_events": len(responses),
        "alerts_triggered": sum(len(item.triggered_alerts) for item in responses),
        "items": [item.model_dump(mode="json") for item in responses],
    }


@router.get(
    "/events",
    status_code=status.HTTP_200_OK,
    summary="List ingested security/log events with filters and pagination",
)
async def list_defense_events(
    session: SessionDep,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=500),
    source_system: str | None = Query(default=None),
    source_ip: str | None = Query(default=None),
    host_id: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
    repository_id: int | None = Query(default=None),
    date_from: datetime.datetime | None = Query(default=None),
    date_to: datetime.datetime | None = Query(default=None),
) -> dict[str, Any]:
    if date_from and date_to and date_from > date_to:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="'date_from' must be earlier than or equal to 'date_to'.",
        )

    stmt = select(DefenseLogEvent)
    if source_system:
        stmt = stmt.where(DefenseLogEvent.source_system == source_system)
    if source_ip:
        stmt = stmt.where(DefenseLogEvent.source_ip == source_ip)
    if host_id:
        stmt = stmt.where(DefenseLogEvent.host_id == host_id)
    if event_type:
        stmt = stmt.where(DefenseLogEvent.event_type == event_type)
    if repository_id is not None:
        stmt = stmt.where(DefenseLogEvent.repository_id == repository_id)
    if date_from is not None:
        stmt = stmt.where(DefenseLogEvent.event_time >= date_from)
    if date_to is not None:
        stmt = stmt.where(DefenseLogEvent.event_time <= date_to)

    offset = (page - 1) * page_size
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = int(session.exec(count_stmt).one())

    paginated_stmt = stmt.order_by(desc(DefenseLogEvent.event_time)).offset(offset).limit(page_size)
    items = list(session.exec(paginated_stmt).all())

    return {
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total_events": total,
            "total_pages": (total + page_size - 1) // page_size if total > 0 else 0,
        },
        "items": [DefenseLogEventRead.model_validate(e).model_dump(mode="json") for e in items],
    }


@router.post(
    "/rules/seed",
    status_code=status.HTTP_200_OK,
    summary="Create/update default behavior rules in database",
)
async def seed_defense_rules(session: SessionDep) -> dict[str, Any]:
    service = _service(session)
    rules = service.ensure_default_rules(sync_existing=True)
    return {
        "rules_seeded": len(rules),
        "codes": [r.code for r in rules],
    }


@router.get(
    "/rules",
    status_code=status.HTTP_200_OK,
    summary="List behavior rules",
    response_model=list[ThreatPatternRuleRead],
)
async def list_defense_rules(session: SessionDep):
    service = _service(session)
    service.ensure_default_rules()
    return service.list_rules()


@router.patch(
    "/rules/{rule_id}",
    status_code=status.HTTP_200_OK,
    summary="Update one behavior rule",
    response_model=ThreatPatternRuleRead,
)
async def update_defense_rule(
    rule_id: int,
    payload: ThreatPatternRuleUpdate,
    session: SessionDep,
):
    rule = session.get(ThreatPatternRule, rule_id)
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule '{rule_id}' not found.")

    data = payload.model_dump(exclude_unset=True)
    for key, value in data.items():
        setattr(rule, key, value)
    rule.updated_at = datetime.datetime.utcnow()

    session.add(rule)
    session.commit()
    session.refresh(rule)
    return ThreatPatternRuleRead.model_validate(rule)


@router.get(
    "/alerts",
    status_code=status.HTTP_200_OK,
    summary="List generated alerts with filters and pagination",
)
async def list_defense_alerts(
    session: SessionDep,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
    status_filter: str | None = Query(default=None, alias="status"),
    severity: str | None = Query(default=None),
    rule_code: str | None = Query(default=None),
    source_system: str | None = Query(default=None),
    repository_id: int | None = Query(default=None),
) -> dict[str, Any]:
    stmt = select(ThreatAlert)
    if status_filter:
        stmt = stmt.where(ThreatAlert.status == status_filter.upper())
    if severity:
        stmt = stmt.where(ThreatAlert.severity == severity.upper())
    if rule_code:
        stmt = stmt.where(ThreatAlert.rule_code == rule_code)
    if source_system:
        stmt = stmt.where(ThreatAlert.source_system == source_system)
    if repository_id is not None:
        stmt = stmt.where(ThreatAlert.repository_id == repository_id)

    offset = (page - 1) * page_size
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = int(session.exec(count_stmt).one())

    paginated_stmt = stmt.order_by(desc(ThreatAlert.created_at)).offset(offset).limit(page_size)
    items = list(session.exec(paginated_stmt).all())

    return {
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total_alerts": total,
            "total_pages": (total + page_size - 1) // page_size if total > 0 else 0,
        },
        "items": [ThreatAlertRead.model_validate(a).model_dump(mode="json") for a in items],
    }


@router.get(
    "/alerts/{alert_id}",
    status_code=status.HTTP_200_OK,
    summary="Get one alert by id",
    response_model=ThreatAlertRead,
)
async def get_defense_alert(alert_id: int, session: SessionDep):
    alert = session.get(ThreatAlert, alert_id)
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Alert '{alert_id}' not found.")
    return ThreatAlertRead.model_validate(alert)


@router.patch(
    "/alerts/{alert_id}/status",
    status_code=status.HTTP_200_OK,
    summary="Update alert status (OPEN, ACKNOWLEDGED, RESOLVED)",
    response_model=ThreatAlertRead,
)
async def update_defense_alert_status(
    alert_id: int,
    payload: ThreatAlertStatusUpdate,
    session: SessionDep,
):
    alert = session.get(ThreatAlert, alert_id)
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Alert '{alert_id}' not found.")

    normalized = payload.status.strip().upper()
    if normalized not in {"OPEN", "ACKNOWLEDGED", "RESOLVED"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid alert status. Allowed: OPEN, ACKNOWLEDGED, RESOLVED.",
        )

    alert.status = normalized
    alert.updated_at = datetime.datetime.utcnow()
    session.add(alert)
    session.commit()
    session.refresh(alert)
    logger.info(f"[Defense] Alert {alert.id} updated to status={normalized}.")
    return ThreatAlertRead.model_validate(alert)
