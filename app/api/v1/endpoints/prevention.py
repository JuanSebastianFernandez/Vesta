from fastapi import APIRouter, HTTPException, status
from app.models.prevention_models import AnalyzeRepoRequest, AnalysisReportResponse
from app.core.exceptions import RepositoryError, AnalysisError, ModelLoadingError


router = APIRouter(
    prefix="/prevention",
    tags=["Prevention Module"]
)

@router.post("/analayze-repository")
async def analyze_repository_manual(request_data: AnalyzeRepoRequest) -> list[AnalysisReportResponse]:
    """
    Start static analysis and AI prediction of a Git repository manually.
    The repository will be cloned (or updated if it already exists) and then analyzed.
    """
    try:
        print()
    
    except RepositoryError as e:
        raise HTTPException(status_code=e.status_code, detail=f"Error in the repository: {e.detail}")
    except AnalysisError as e:
        raise HTTPException(status_code=e.status_code, detail=f"Error during analysis: {e.detail}")
    except ModelLoadingError as e:
        raise HTTPException(status_code=e.status_code, detail=f"Error charging ML models: {e.detail}")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Unexpected error happened: {str(e)}")
