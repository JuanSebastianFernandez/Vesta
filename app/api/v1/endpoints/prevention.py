import hmac
import hashlib
import json
from fastapi import APIRouter, HTTPException, status, Request, Header, Depends, BackgroundTasks
from fastapi.responses import JSONResponse
from typing import Any, Annotated
from app.models.prevention_models import *
from app.core.exceptions import RepositoryError, AnalysisError, ModelLoadingError
from app.services.repository_manager import RepositoryManager
from app.services.report_service import ReportService
from app.core.config import settings
from db.database import get_session, engine
from app.utilities.logger import logger
from sqlmodel import Session

router = APIRouter(
    prefix="/prevention",
    tags=["Prevention Module"]
)

SessionDep = Annotated[Session, Depends(get_session)]
repo_manager = RepositoryManager()



@router.get("/")
async def prevention_root() -> dict[str, Any]:
    return {"message": "Prevention Module API is working well."}

async def _analyze_repository_impl(request_data: RepositoryCreate, session: SessionDep):
    """
    Start static analysis and AI prediction of a Git repository manually.
    The repository will be cloned (or updated if it already exists) and then analyzed.
    """
    report_service = ReportService(session=session)
    try:
        raw_reports = repo_manager.process_repository(
            repo_url=str(request_data.url), 
            repo_name=request_data.url.split("/")[-1].replace(".git",""),
            commit_hash=request_data.commit_hash    
        )
        logger.info(f"Number of raw reports: {len(raw_reports)}")

        response_reports = report_service.process_and_respond(
            raw_reports=raw_reports, 
            repository_create=request_data
        )
        
        return response_reports
    
    except RepositoryError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Error in the repository: {e.detail}")
    except AnalysisError as e:
        raise HTTPException(status_code=e.status_code, detail=f"Error during analysis: {e.detail}")
    except ModelLoadingError as e:
        raise HTTPException(status_code=e.status_code, detail=f"Error charging ML models: {e.detail}")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Unexpected error happened: {str(e)}")

@router.post("/analyze-repository", 
                status_code=status.HTTP_200_OK, 
                summary="Start static analysis and AI prediction of a Git repository", 
                response_model=list[ReportReadWithRepository], 
                response_model_exclude_unset=True, 
                response_model_exclude_none=True)
async def analyze_repository_manual(request_data: RepositoryCreate, session: SessionDep):
    return await _analyze_repository_impl(request_data=request_data, session=session)

@router.post("/analayze-repository",
                status_code=status.HTTP_200_OK,
                summary="[DEPRECATED] Start static analysis and AI prediction of a Git repository",
                response_model=list[ReportReadWithRepository],
                response_model_exclude_unset=True,
                response_model_exclude_none=True,
                deprecated=True)
async def analyze_repository_manual_legacy(request_data: RepositoryCreate, session: SessionDep):
    logger.warning("Deprecated endpoint '/prevention/analayze-repository' used. Use '/prevention/analyze-repository' instead.")
    return await _analyze_repository_impl(request_data=request_data, session=session)


def _process_github_push_background(repo_url: str, repo_name: str, head_commit_id: str, delivery_id: str) -> None:
    """
    Process GitHub push events out-of-band to avoid webhook timeouts.
    """
    try:
        logger.info(
            f"[GitHub webhook background] start delivery={delivery_id} repo='{repo_name}' commit='{head_commit_id}'"
        )
        raw_reports = repo_manager.process_repository(
            repo_url=repo_url,
            repo_name=repo_name,
            commit_hash=head_commit_id,
        )
        with Session(engine) as bg_session:
            report_service = ReportService(session=bg_session)
            response_reports = report_service.process_and_respond(
                raw_reports=raw_reports,
                repository_create=RepositoryCreate(url=repo_url, commit_hash=head_commit_id),
            )
        logger.info(
            f"[GitHub webhook background] done delivery={delivery_id} "
            f"reports_total={len(response_reports)}"
        )
    except Exception as e:
        logger.exception(f"[GitHub webhook background] failed delivery={delivery_id}: {e}")


@router.post("/webhooks/github", status_code=status.HTTP_200_OK, summary="Get and process Github webhook")
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature_256: Annotated[str | None, Header()] = None,
    x_github_delivery: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    """
    Endpoint to receive and process GitHub webhooks.
    Supports:
    - ping: handshake
    - push: repository analysis trigger
    """
    if not x_hub_signature_256:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Webhook signature not provided (X-Hub-Signature-256).",
        )

    body = await request.body()
    secret = settings.GITHUB_WEBHOOK_SECRET.encode("utf-8")

    try:
        hash_algorithm, github_signature = x_hub_signature_256.split("=", 1)
        if hash_algorithm != "sha256":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unsupported signature algorithm. Expected sha256.",
            )

        mac = hmac.new(key=secret, msg=body, digestmod=hashlib.sha256)
        if not hmac.compare_digest(mac.hexdigest(), github_signature):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid webhook signature.",
            )
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid signature format in X-Hub-Signature-256.",
        )

    try:
        payload: dict[str, Any] = json.loads(body.decode("utf-8")) if body else {}
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON payload.",
        )

    event_type = request.headers.get("X-GitHub-Event", "unknown")

    if event_type == "ping":
        return {"message": "Webhook ping received successfully."}

    if event_type != "push":
        return {"message": f"GitHub event '{event_type}' received but not processed."}

    repo_url = payload.get("repository", {}).get("clone_url")
    repo_name = payload.get("repository", {}).get("name")
    head_commit_id = payload.get("head_commit", {}).get("id") or payload.get("after")
    if not all([repo_url, repo_name, head_commit_id]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incomplete push payload. Missing repository clone_url/name or commit SHA.",
        )

    delivery_id = x_github_delivery or "unknown-delivery-id"
    logger.info(
        f"'push' event accepted for repository '{repo_name}'. Commit: {head_commit_id}. "
        f"delivery_id={delivery_id}"
    )
    background_tasks.add_task(
        _process_github_push_background,
        repo_url,
        repo_name,
        head_commit_id,
        delivery_id,
    )

    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content={
            "message": "Push event received and analysis scheduled.",
            "repository": repo_name,
            "commit": head_commit_id,
            "delivery_id": delivery_id,
            "status": "ACCEPTED",
        },
    )
