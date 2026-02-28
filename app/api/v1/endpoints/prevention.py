import hmac
import hashlib
import json
import datetime
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


def _normalize_repo_name(repo_url: str) -> str:
    return repo_url.rstrip("/").split("/")[-1].replace(".git", "")


def _extract_security_status(item: Any) -> str:
    if isinstance(item, dict):
        return str(item.get("security_status", "UNKNOWN"))
    return str(getattr(item, "security_status", "UNKNOWN"))


def _summarize_analysis_results(results: list[Any]) -> dict[str, Any]:
    status_counts: dict[str, int] = {
        "BENIGN": 0,
        "SUSPICIOUS": 0,
        "MALICIOUS": 0,
        "SKIPPED": 0,
        "ANALYSIS_ERROR": 0,
        "POTENTIALLY_MALFORMED": 0,
        "UNKNOWN": 0,
    }
    for item in results:
        status_value = _extract_security_status(item).upper()
        if status_value in status_counts:
            status_counts[status_value] += 1
        else:
            status_counts["UNKNOWN"] += 1
    return {
        "total_reports": len(results),
        "status_counts": status_counts,
    }

def _compact_report_result(item: Any) -> dict[str, Any]:
    if isinstance(item, dict):
        repository_obj = item.get("repository") or {}
        return {
            "file_hash": item.get("file_hash"),
            "file_name": item.get("file_name"),
            "language": item.get("language"),
            "label": item.get("label"),
            "prediction_probability": item.get("prediction_probability"),
            "risk_score": item.get("risk_score"),
            "prediction_source": item.get("prediction_source"),
            "amount_findings": item.get("amount_findings"),
            "security_status": item.get("security_status"),
            "message": item.get("message"),
            "repository_id": repository_obj.get("id"),
            "repository_url": repository_obj.get("url"),
        }

    repository_obj = getattr(item, "repository", None)
    return {
        "file_hash": getattr(item, "file_hash", None),
        "file_name": getattr(item, "file_name", None),
        "language": getattr(item, "language", None),
        "label": getattr(item, "label", None),
        "prediction_probability": getattr(item, "prediction_probability", None),
        "risk_score": getattr(item, "risk_score", None),
        "prediction_source": getattr(item, "prediction_source", None),
        "amount_findings": getattr(item, "amount_findings", None),
        "security_status": getattr(item, "security_status", None),
        "message": getattr(item, "message", None),
        "repository_id": getattr(repository_obj, "id", None) if repository_obj else None,
        "repository_url": getattr(repository_obj, "url", None) if repository_obj else None,
    }


def _run_analysis_job_background(job_id: str) -> None:
    with Session(engine) as bg_session:
        job = bg_session.get(AnalysisJob, job_id)
        if not job:
            logger.error(f"[Job runner] AnalysisJob '{job_id}' not found.")
            return

        try:
            job.status = "RUNNING"
            job.started_at = datetime.datetime.utcnow()
            bg_session.add(job)
            bg_session.commit()
            bg_session.refresh(job)

            raw_reports = repo_manager.process_repository(
                repo_url=job.repository_url,
                repo_name=job.repository_name,
                commit_hash=job.commit_hash,
            )
            report_service = ReportService(session=bg_session)
            response_reports = report_service.process_and_respond(
                raw_reports=raw_reports,
                repository_create=RepositoryCreate(url=job.repository_url, commit_hash=job.commit_hash),
            )

            job.status = "DONE"
            job.finished_at = datetime.datetime.utcnow()
            job.error_message = None
            job.result_summary = {
                "summary": _summarize_analysis_results(response_reports),
                "reports": [_compact_report_result(item) for item in response_reports],
            }
            bg_session.add(job)
            bg_session.commit()
            logger.info(f"[Job runner] AnalysisJob '{job_id}' completed.")
        except Exception as e:
            bg_session.rollback()
            job = bg_session.get(AnalysisJob, job_id)
            if job:
                job.status = "FAILED"
                job.finished_at = datetime.datetime.utcnow()
                job.error_message = str(e)[:4000]
                bg_session.add(job)
                bg_session.commit()
            logger.exception(f"[Job runner] AnalysisJob '{job_id}' failed: {e}")



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

@router.post(
    "/analyze-repository-async",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Create async analysis job and return job id immediately",
)
async def analyze_repository_async(
    request_data: RepositoryCreate,
    background_tasks: BackgroundTasks,
    session: SessionDep,
) -> dict[str, Any]:
    repo_url = str(request_data.url)
    job = AnalysisJob(
        repository_url=repo_url,
        repository_name=_normalize_repo_name(repo_url),
        commit_hash=request_data.commit_hash,
        trigger_source="MANUAL",
        status="PENDING",
    )
    session.add(job)
    session.commit()
    session.refresh(job)

    background_tasks.add_task(_run_analysis_job_background, job.id)
    return {
        "message": "Analysis job created and scheduled.",
        "job_id": job.id,
        "status": job.status,
    }


@router.get(
    "/jobs/{job_id}",
    status_code=status.HTTP_200_OK,
    summary="Get status of an async analysis job",
    response_model=AnalysisJobRead,
)
async def get_analysis_job(job_id: str, session: SessionDep):
    job = session.get(AnalysisJob, job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Job '{job_id}' not found.")
    return job


@router.get(
    "/jobs/{job_id}/result",
    status_code=status.HTTP_200_OK,
    summary="Get final result payload for an async analysis job",
)
async def get_analysis_job_result(job_id: str, session: SessionDep):
    job = session.get(AnalysisJob, job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Job '{job_id}' not found.")

    if job.status in {"PENDING", "RUNNING"}:
        return JSONResponse(
            status_code=status.HTTP_202_ACCEPTED,
            content={
                "message": f"Job '{job_id}' is not finished yet.",
                "job_id": job_id,
                "status": job.status,
            },
        )

    if job.status == "FAILED":
        return {
            "job_id": job_id,
            "status": job.status,
            "error_message": job.error_message,
            "result": job.result_summary or {},
        }

    return {
        "job_id": job_id,
        "status": job.status,
        "result": job.result_summary or {},
    }


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
