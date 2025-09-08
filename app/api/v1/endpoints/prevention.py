import hmac
import hashlib
from fastapi import APIRouter, HTTPException, status, Request, Header, Body, Depends
from typing import Any, Annotated
from app.models.prevention_models import *
from app.core.exceptions import RepositoryError, AnalysisError, ModelLoadingError
from app.services.repository_manager import RepositoryManager
from app.services.report_service import ReportService
from app.core.config import settings
from db.database import get_session
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

@router.post("/analayze-repository", 
                status_code=status.HTTP_200_OK, 
                summary="Start static analysis and AI prediction of a Git repository", 
                response_model=list[ReportReadWithRepository], 
                response_model_exclude_unset=True, 
                response_model_exclude_none=True)
async def analyze_repository_manual(request_data: RepositoryCreate, session: SessionDep):
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

# @router.post("/webhooks/github", status_code=status.HTTP_200_OK, summary="Get and process Github webhook")
# async def github_webhook(request: Request,
#                         x_hub_signature_256: Annotated[str|None, Header()] = None, # GitHub Signature
#                         payload: dict = Body()            # Json Body by webhook
#                         ) -> dict[str, Any]:
#     """
#     Endpoint to get and process Github webhook.
#     Detects 'push' events in the repositories and triggers the analysis.
#     """
#     if not x_hub_signature_256:
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Webhook signature not provided (X-Hub-Signature).")

#     # Check signature
#     body = await request.body()
#     secret = settings.GITHUB_WEBHOOK_SECRET.encode('utf-8')
#     try:
#         hash_algorithm, github_signature = x_hub_signature_256.split('=', 1)
#         if hash_algorithm != 'sha256':
#             raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Siganture hash algorithm not supported. It's expected 'sha256'.")

#         mac = hmac.new(key = secret, msg = body, digestmod = hashlib.sha256)  # Turning the secret in a hash to validate with hash header 
#         if not hmac.compare_digest(mac.hexdigest(), github_signature):
#             raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Webhook signature invalid. It isn't authentic")

#     except ValueError:
#         raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Webhook signature format invalid.")
#     except Exception as e:
#         raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error during verification of signature: {str(e)}")
    
#     # Process pyload
#     event_type = request.headers.get("X-GitHub-Event", "unknown")

#     if event_type == "ping":
#         return {"message": "Webhook ping received successfully."}
#     elif event_type == "push":
#         repo_url = payload.get("repository", {}).get("clone_url")
#         repo_name = payload.get("repository", {}).get("name")
#         head_commit_id = payload.get("head_commit", {}).get("id") # SHA of the last commit
#         if not all([repo_url, repo_name, head_commit_id]):
#             raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Webhook Payload 'push' uncomplete. Missing Repo URL, name or SHA ID of the last commit.")
#         try:
#             print(f"'push' Event detected for repository {repo_name}. Commit: {head_commit_id}")
#             # 3. Start analysis process
#             reports = repo_manager.process_repository(
#                 repo_url = repo_url, 
#                 repo_name = repo_name, 
#                 commit_hash = head_commit_id
#                 )

#             full_reports_with_ml_prediction = []
#             for report in reports:
#                 processed_report = _process_single_analysis_report(report = report)
#                 full_reports_with_ml_prediction.append(processed_report)

#             return {
#                 "message": f"Analysis of repository {repo_name} - commit {head_commit_id} completed successfully.",
#                 "analysis_results": full_reports_with_ml_prediction
#             }
#         except RepositoryError as e:
#             raise HTTPException(status_code=e.status_code, detail=f"Repository error: {e.detail}")
#         except AnalysisError as e:
#             raise HTTPException(status_code=e.status_code, detail=f"Error during analysis: {e.detail}")
#         except ModelLoadingError as e:
#             raise HTTPException(status_code=e.status_code, detail=f"Error chargin ML models: {e.detail}")
#         except Exception as e:
#             raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Unexpected error with the webhook: {str(e)}")
#     else:
#         return {"message": f"GitHub Event'{event_type}' received but not processed."}