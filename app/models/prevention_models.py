from pydantic import BaseModel, Field, HttpUrl
from typing import Any


class FeatureVector(BaseModel):
    section_max_entropy: float
    size_of_stack_reserve: float
    sections_min_virtualsize: float
    resources_min_entropy: float
    major_linker_version: float
    size_of_optional_header: float
    address_of_entry_point: float
    sections_min_entropy: float
    minor_operating_system_version: float
    section_alignment: float
    size_of_headers: float
    loader_flags: float

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
    amount_findings: int | None = None
    feature_vector: FeatureVector | None = None
    static_findings: list[StaticFinding] | None = None
    parsing_errors: list[dict[str, Any]] | None = None
    message: str | None = None
    ml_prediction: MLPrediction | None = None
    secuity_status: str | None = None

class AnalyzeRepoRequest(BaseModel):
    repo_url: HttpUrl = Field(
        examples = ["https://github.com/octocat/Spoon-Knife"],
        description = "URL of the repository to analyze."
    )


if __name__ == "__main__":
    # Test for making objects and validate that classes are working well
    analyzer = AnalysisReportResponse(
        file_path="/home/documents/js", 
        status="SUCCESS",
        amount_findings=1,
        feature_vector=FeatureVector(
            section_max_entropy=1.0,
            size_of_stack_reserve=2.0,
            sections_min_virtualsize=3.0,
            resources_min_entropy=4.0,
            major_linker_version=5.0,
            size_of_optional_header=6.0,
            address_of_entry_point=7.0,
            sections_min_entropy=8.0,
            minor_operating_system_version=9.0,
            section_alignment=10.0,
            size_of_headers=11.0,
            loader_flags=12.0
        ),
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
        secuity_status="BENIGN"
    )
    print(analyzer)