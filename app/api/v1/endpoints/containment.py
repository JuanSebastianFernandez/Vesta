from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlmodel import Session

from app.models.containment_models import (
    BlockIpRequest,
    ContainmentActionAuditRead,
    ContainmentActionResponse,
    ContainmentActionStatusUpdate,
    DeployHoneypotRequest,
    IsolateNodeRequest,
    RestoreBackupRequest,
)
from app.services.containment_service import ContainmentService
from db.database import get_session


router = APIRouter(
    prefix="/containment",
    tags=["Containment Module"],
)

SessionDep = Annotated[Session, Depends(get_session)]


def _service(session: SessionDep) -> ContainmentService:
    return ContainmentService(session=session)


@router.get("/")
async def containment_root() -> dict[str, str]:
    return {"message": "Containment module is available."}


@router.post(
    "/isolate-node",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ContainmentActionResponse,
    summary="Contain compromised node (stub) and audit the action",
)
async def isolate_node(payload: IsolateNodeRequest, session: SessionDep):
    service = _service(session)
    try:
        return service.isolate_node(payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post(
    "/block-ip",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ContainmentActionResponse,
    summary="Block malicious IP/rule (stub) and audit the action",
)
async def block_ip(payload: BlockIpRequest, session: SessionDep):
    service = _service(session)
    try:
        return service.block_ip(payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post(
    "/restore-backup",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ContainmentActionResponse,
    summary="Start backup restoration workflow (stub) and audit the action",
)
async def restore_backup(payload: RestoreBackupRequest, session: SessionDep):
    service = _service(session)
    try:
        return service.restore_backup(payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post(
    "/deploy-honeypot",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ContainmentActionResponse,
    summary="Deploy honeypot/deception profile (stub) and audit the action",
)
async def deploy_honeypot(payload: DeployHoneypotRequest, session: SessionDep):
    service = _service(session)
    try:
        return service.deploy_honeypot(payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.get(
    "/actions",
    status_code=status.HTTP_200_OK,
    summary="List containment audit actions with filters and pagination",
)
async def list_actions(
    session: SessionDep,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=500),
    action_type: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    requested_by: str | None = Query(default=None),
    repository_id: int | None = Query(default=None),
    source_alert_id: int | None = Query(default=None),
) -> dict:
    service = _service(session)
    return service.list_actions(
        page=page,
        page_size=page_size,
        action_type=action_type,
        status=status_filter,
        requested_by=requested_by,
        repository_id=repository_id,
        source_alert_id=source_alert_id,
    )


@router.get(
    "/actions/{action_id}",
    status_code=status.HTTP_200_OK,
    response_model=ContainmentActionAuditRead,
    summary="Get one containment action audit by id",
)
async def get_action(action_id: int, session: SessionDep):
    service = _service(session)
    action = service.get_action(action_id)
    if not action:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Action '{action_id}' not found.")
    return action


@router.patch(
    "/actions/{action_id}/status",
    status_code=status.HTTP_200_OK,
    response_model=ContainmentActionAuditRead,
    summary="Update containment action status for operational traceability",
)
async def update_action_status(action_id: int, payload: ContainmentActionStatusUpdate, session: SessionDep):
    service = _service(session)
    try:
        action = service.update_action_status(action_id, payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    if not action:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Action '{action_id}' not found.")
    return action
