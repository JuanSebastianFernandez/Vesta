from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlmodel import Session

from app.models.demo_models import DemoScenarioRunRequest
from app.services.demo_scenario_service import DemoScenarioService
from db.database import get_session


router = APIRouter(
    prefix="/demo",
    tags=["Demo Runtime"],
)

SessionDep = Annotated[Session, Depends(get_session)]


def _service(session: SessionDep) -> DemoScenarioService:
    return DemoScenarioService(session=session)


@router.get("/")
async def demo_root() -> dict[str, str]:
    return {"message": "Demo runtime module is available."}


@router.post(
    "/scenarios/{scenario_code}/run",
    status_code=status.HTTP_200_OK,
    summary="Run a reproducible demo scenario against the defense/containment stack",
)
async def run_demo_scenario(
    scenario_code: str,
    session: SessionDep,
    payload: DemoScenarioRunRequest | None = None,
) -> dict[str, Any]:
    service = _service(session)
    try:
        return service.run_scenario(scenario_code, payload or DemoScenarioRunRequest())
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.get(
    "/runtime/assets",
    status_code=status.HTTP_200_OK,
    summary="Get Docker lab runtime assets and current containment state",
)
async def get_demo_runtime_assets(session: SessionDep) -> dict[str, Any]:
    return _service(session).list_runtime_assets()


@router.get(
    "/runtime/timeline",
    status_code=status.HTTP_200_OK,
    summary="Get a unified demo timeline from analysis, defense and containment",
)
async def get_demo_runtime_timeline(
    session: SessionDep,
    limit: int = Query(default=50, ge=1, le=200),
) -> dict[str, Any]:
    return _service(session).build_timeline(limit=limit)

