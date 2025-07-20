from pydantic import BaseModel, Field, HttpUrl
from typing import Any


class StaticFinding(BaseModel):
    finding_type: str
    description: str
    line: int
    severity: str

class MLPrediction(BaseModel):
    prediction_probability: float
    prediction_binary: int


class AnalysisReportResponse(BaseModel):
    file_path: str
    status: str
    amount_findings: int
    feature_vector: dict[str, Any] | None = None
    static_findings: list[StaticFinding] | None = None
    parsing_errors: list[dict[str, Any]] | None = None
    message: str | None = None
    ml_prediction: MLPrediction | None = None
    security_status: str | None = None

class AnalyzeRepoRequest(BaseModel):
    repo_url: HttpUrl = Field(
        examples = ["https://github.com/octocat/Spoon-Knife"],
        description = "URL of the repository to analyze."
    )
    repo_name: str = Field(
        examples = ["Spoon-Knife-Project"],
        description = "Name of the local folder to clone/update repository"
    )
    # Add commit hash when need to analyze a especific commit of a git repository
    commit_hash: str | None = Field(
        default = None,
        examples = ["a1b2c3d4e5f6sadddda45er45rwe5vbvjhhrihgdfs"],
        description = "Hash of the specific commit to analyze. If it's none, the last one is used (Head location)"
    )


if __name__ == "__main__":
    # Test for making objects and validate that classes are working well
    analyzer = AnalysisReportResponse(
        file_path="/home/documents/js", 
        status="SUCCESS",
        amount_findings=1,
        feature_vector={
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
        static_findings=[
            StaticFinding(
                finding_type="SELF_AWARE_BEHAVIOR",
                description="Code attempts to access its own execution path",
                line=2,
                severity="HIGH"
            ),
            StaticFinding(
                finding_type="IMPROPER_ERROR_HANDLING",
                description="Code contains a string that appears to be a sensitive system file",
                line=1,
                severity="MEDIUM"
            )
        ],
        parsing_errors=[
            {
                "line": 1,
                "column": 20,
                "message": "extraneous input ':' expecting {')', '*', '**', 'type', 'match', 'case', '_', NAME}",
                "offending_symbol": ":"
            },
            {
                "line": 2,
                "column": 9,
                "message": "mismatched input '(' expecting ')'",
                "offending_symbol": "("
            }
        ],
        message="Analysis successful",
        ml_prediction=MLPrediction(
            prediction_probability=0.95,
            prediction_binary=1
        ),
        security_status="BENIGN"
    )
    print(analyzer)