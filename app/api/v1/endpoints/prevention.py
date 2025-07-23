import hmac
import hashlib
from fastapi import APIRouter, HTTPException, status, Request, Header, Body
from pydantic import ValidationError
from typing import Any, Annotated
from app.models.prevention_models import *
from app.core.exceptions import RepositoryError, AnalysisError, ModelLoadingError
from app.services.repository_manager import RepositoryManager
from app.services.ml_prediction import predict_malware_risk
from app.core.config import settings


router = APIRouter(
    prefix="/prevention",
    tags=["Prevention Module"]
)

repo_manager = RepositoryManager()

@router.get("/")
async def prevention_root() -> dict[str, Any]:
    return {"message": "Prevention Module API is working well."}

@router.post("/analayze-repository", 
                status_code=status.HTTP_200_OK, 
                summary="Start static analysis and AI prediction of a Git repository", 
                response_model=list[AnalysisReportResponse], 
                response_model_exclude_unset=True, 
                response_model_exclude_none=True)
async def analyze_repository_manual(request_data: AnalyzeRepoRequest) -> list[AnalysisReportResponse]:
    """
    Start static analysis and AI prediction of a Git repository manually.
    The repository will be cloned (or updated if it already exists) and then analyzed.
    """
    try:
        reports = repo_manager.process_repository(
            repo_url=str(request_data.repo_url), 
            repo_name=request_data.repo_name,
            commit_hash=request_data.commit_hash    
        )

        full_reports_with_ml_prediction = []
        for report in reports:
            processed_report = _process_single_analysis_report(report = report)
            full_reports_with_ml_prediction.append(processed_report)
        
        return full_reports_with_ml_prediction
    
    except RepositoryError as e:
        raise HTTPException(status_code=e.status_code, detail=f"Error in the repository: {e.detail}")
    except AnalysisError as e:
        raise HTTPException(status_code=e.status_code, detail=f"Error during analysis: {e.detail}")
    except ModelLoadingError as e:
        raise HTTPException(status_code=e.status_code, detail=f"Error charging ML models: {e.detail}")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Unexpected error happened: {str(e)}")

@router.post("/webhooks/github", status_code=status.HTTP_200_OK, summary="Get and process Github webhook")
async def github_webhook(request: Request,
                        x_hub_signature_256: Annotated[str|None, Header()] = None, # GitHub Signature
                        payload: dict = Body()            # Json Body by webhook
                        ) -> dict[str, Any]:
    """
    Endpoint to get and process Github webhook.
    Detects 'push' events in the repositories and triggers the analysis.
    """
    if not x_hub_signature_256:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Webhook signature not provided (X-Hub-Signature).")

    # Check signature
    body = await request.body()
    secret = settings.GITHUB_WEBHOOK_SECRET.encode('utf-8')
    try:
        hash_algorithm, github_signature = x_hub_signature_256.split('=', 1)
        if hash_algorithm != 'sha256':
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Siganture hash algorithm not supported. It's expected 'sha256'.")

        mac = hmac.new(key = secret, msg = body, digestmod = hashlib.sha256)  # Turning the secret in a hash to validate with hash header 
        if not hmac.compare_digest(mac.hexdigest(), github_signature):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Webhook signature invalid. It isn't authentic")

    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Webhook signature format invalid.")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error during verification of signature: {str(e)}")
    
    # Process pyload
    event_type = request.headers.get("X-GitHub-Event", "unknown")

    if event_type == "ping":
        return {"message": "Webhook ping received successfully."}
    elif event_type == "push":
        repo_url = payload.get("repository", {}).get("clone_url")
        repo_name = payload.get("repository", {}).get("name")
        head_commit_id = payload.get("head_commit", {}).get("id") # SHA of the last commit
        if not all([repo_url, repo_name, head_commit_id]):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Webhook Payload 'push' uncomplete. Missing Repo URL, name or SHA ID of the last commit.")
        try:
            print(f"'push' Event detected for repository {repo_name}. Commit: {head_commit_id}")
            # 3. Start analysis process
            reports = repo_manager.process_repository(
                repo_url = repo_url, 
                repo_name = repo_name, 
                commit_hash = head_commit_id
                )

            full_reports_with_ml_prediction = []
            for report in reports:
                processed_report = _process_single_analysis_report(report = report)
                full_reports_with_ml_prediction.append(processed_report)

            return {
                "message": f"Analysis of repository {repo_name} - commit {head_commit_id} completed successfully.",
                "analysis_results": full_reports_with_ml_prediction
            }
        except RepositoryError as e:
            raise HTTPException(status_code=e.status_code, detail=f"Repository error: {e.detail}")
        except AnalysisError as e:
            raise HTTPException(status_code=e.status_code, detail=f"Error during analysis: {e.detail}")
        except ModelLoadingError as e:
            raise HTTPException(status_code=e.status_code, detail=f"Error chargin ML models: {e.detail}")
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Unexpected error with the webhook: {str(e)}")
    else:
        return {"message": f"GitHub Event'{event_type}' received but not processed."}


def _process_single_analysis_report(report: dict[str, Any]) -> dict[str, Any]:
    """
    Process a single analysis report (After ANTLR) for adding the ML prediction.
    Decide: Security status for the report
    Modeling: ml_prediction and static_findings
    """

    def process_state():
        if report["status"] == "SUCCESS" and report["feature_vector"]:
            try:
                ml_prediction = predict_malware_risk(report["feature_vector"])
                report["ml_prediction"] = MLPrediction(**ml_prediction)
                if ml_prediction["prediction_binary"] == 0:   # Malware
                    report["security_status"] = "MALICIOUS"
                    report["message"] = f"The file is probably malicious with a probability of {ml_prediction['prediction_probability']*100:.2f}%"
                else:
                    report["security_status"] = "BENIGN"
                    report["message"] = f"The file is cosidered bening with a probability of {ml_prediction['prediction_probability']*100:.2f}%"
            except (ModelLoadingError, AnalysisError) as e:
                report["status"] = "ML_PREDICTION_FAILED"
                report["message"] = f"ML prediction failed for this file: {e.detail}"

        elif report["status"] == "PARSING_ERRORS":
            report["security_status"] = "POTENTIALLY_MALFORMED"
            report["message"] = "The file contains sintax errors, it could indicate obfuscation or malformed code."
        elif report["status"] == "UNSUPPORTED_LANGUAGE":
            report["security_status"] = "SKIPPED"
            report["message"] = f"File Skiped: {report['message']}"
            report["feature_vector"] = None
        elif report["status"] == "ANALYSIS_FAILED":
            report["security_status"] = "ANALYSIS_ERROR"
            report["message"] = f"General analysis error: {report['message']}"
            report["feature_vector"] = None
    
    def process_static_findings():
        if report["amount_findings"] > 0:
            try:
                report["static_findings"] = [StaticFinding(**static_finding) for static_finding in report["static_findings"]]
            except ValidationError as e:
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Error in static_findings parameters: {str(e)}")
            except Exception as e:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Unexpected error happened: {str(e)}")
        else:
            report["static_findings"] = None

    process_state()
    process_static_findings()
    return report
    
    

    
if __name__ == "__main__":
    import json
    data = {
    "feature_vector": {
        "SectionsMaxEntropy": 5.149747596305933,
        "SizeOfStackReserve": 2.0,
        "SectionsMinVirtualsize": 192.0,
        "ResourcesMinEntropy": -0.0,
        "MajorLinkerVersion": 1.0,
        "SizeOfOptionalHeader": 1.0,
        "AddressOfEntryPoint": 0.0,
        "SectionsMinEntropy": 4.991356541513986,
        "MinorOperatingSystemVersion": 0.0,
        "SectionAlignment": 0.0,
        "SizeOfHeaders": 1.0,
        "LoaderFlags": 0.0
    },
    "static_findings": [
        {
            "finding_type": "NETWORK_COMMUNICATION",
            "description": "Suspicious import detected: 'java.net.HttpURLConnection'. Indicates: Capacidad de comunicación por red (potencial para exfiltración o C2).",
            "line": 4,
            "severity": "MEDIUM"
        },
        {
            "finding_type": "NETWORK_COMMUNICATION",
            "description": "Suspicious import detected: 'java.net.URL'. Indicates: Capacidad de comunicación por red (potencial para exfiltración o C2).",
            "line": 5,
            "severity": "MEDIUM"
        },
        {
            "finding_type": "CRYPTOGRAPHIC_USE",
            "description": "Suspicious import detected: 'javax.crypto.Cipher'. Indicates: Uso de la API de Criptografía de Java (potencial para cifrado de archivos).",
            "line": 7,
            "severity": "HIGH"
        },
        {
            "finding_type": "CODE_EXECUTION",
            "description": "Use of potentially dangerous method call detected: 'Runtime.getRuntime().exec'",
            "line": 15,
            "severity": "CRITICAL"
        },
        {
            "finding_type": "SENSITIVE_DATA_ACCESS",
            "description": "Sensitive path access detected: 'C:/Windows/System32/drivers/etc/hosts'",
            "line": 18,
            "severity": "HIGH"
        },
        {
            "finding_type": "IMPROPER_ERROR_HANDLING",
            "description": "Empty catch block detected. Swallowing exceptions can mask critical security issues.",
            "line": 37,
            "severity": "MEDIUM"
        },
        {
            "finding_type": "SELF_AWARE_BEHAVIOR",
            "description": "Use of potentially dangerous method call detected: 'getClass().getProtectionDomain().getCodeSource().getLocation'",
            "line": 60,
            "severity": "HIGH"
        },
        {
            "finding_type": "IMPROPER_ERROR_HANDLING",
            "description": "Empty catch block detected. Swallowing exceptions can mask critical security issues.",
            "line": 64,
            "severity": "MEDIUM"
        }
    ],
    "amount_findings": 8,
    "file_path": "C:\\Users\\kidsh\\Documents\\Learning\\antlr4\\codeSamples\\Java\\SuspiciousSample.java",
    "status": "SUCCESS"
}

    report = _process_single_analysis_report(data)
    print(report)