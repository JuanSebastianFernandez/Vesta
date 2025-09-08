from sqlmodel import Session, select
from typing import List, Dict, Any
from app.models.prevention_models import *
# from app.services.ml_prediction import predict_malware_risk
from app.services.codebert_processor import get_code_embedding, load_codebert_model
from app.utilities.security_utils import generate_sha256_hash
from collections import Counter
from sqlalchemy.exc import SQLAlchemyError
from pydantic import ValidationError
from app.core.exceptions import ModelLoadingError
from app.utilities.logger import logger
import numpy as np
import os
import datetime


class ReportService:
    """
    Manages the processing, storage, and retrieval of analysis reports.
    """

    def __init__(self, session: Session):
        self.session = session
        try:
            self.codebert_model, self.codebert_tokenizer = load_codebert_model()
            # self.random_forest_model = load_random_forest_model() # (future usage)
        except Exception as e:
            logger.error(f"Critical error while loading ML models: {e}")
            raise ModelLoadingError(f"Could not load ML models: {e}")

    def _extract_ml_features(self, raw_report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract a dictionary of numerical features from a raw ANTLR report.

        Args:
            raw_report (Dict[str, Any]): The raw report data.

        Returns:
            Dict[str, Any]: A dictionary with computed numerical features.
        """
        try:
            static_findings = raw_report.get("static_findings", [])
            if not static_findings:
                return {}

            weights = [
                f.get("weight", 0.0) for f in static_findings
                if isinstance(f.get("weight"), (int, float))
            ]
            severity_list = [
                f"severity_{f.get('severity', 'unknown').lower()}_count"
                for f in static_findings
            ]
            severity_counts = Counter(severity_list)
            behavioral_triggers = raw_report.get("behavioral_trigger_counts", {})
            trigger_counts = {
                f"trigger_{key}_count": value for key, value in behavioral_triggers.items()
            }

            features = {
                "total_findings": len(static_findings),
                "sum_of_weights": sum(weights),
                "avg_weight": round(float(np.mean(weights)), 4) if weights else 0.0,
                "max_weight": max(weights) if weights else 0.0,
                **severity_counts,
                **trigger_counts,
            }
            return features
        except Exception as e:
            logger.error(f"Error while extracting ML features: {e}")
            return {}

    def _build_response_from_raw(self, raw_report: Dict[str, Any], repository: Repository) -> ReportReadWithRepository:
        """
        Build a response model from a raw report (used for failed cases).
        """
        try:
            status = raw_report.get("status", "ANALYSIS_FAILED")
            message = raw_report.get("message", "Unknown error during analysis.")
            security_status = "UNKNOWN"

            if status == "PARSING_ERRORS":
                security_status = "POTENTIALLY_MALFORMED"
            elif status == "UNSUPPORTED_LANGUAGE":
                security_status = "SKIPPED"
            elif status == "ANALYSIS_FAILED":
                security_status = "ANALYSIS_ERROR"

            findings_list = raw_report.get("static_findings", [])

            return ReportReadWithRepository(
                file_hash=generate_sha256_hash(raw_report.get("original_code", "")),
                file_name=raw_report.get("file_path", "").split(os.sep)[-1][:255],
                language=raw_report.get("language", "unknown"),
                label=None,  # No label for failed reports
                amount_findings=raw_report.get("amount_findings", 0),
                antlr_report=findings_list,
                antlr_features=self._extract_ml_features(raw_report),
                repository=RepositoryRead.model_validate(repository),
                security_status=security_status,
                message=message,
            )
        except ValidationError as e:
            logger.error(f"Validation error while building response from raw report: {e}")
            return ReportReadWithRepository(
                file_hash="invalid_hash",
                file_name="invalid_file",
                language="unknown",
                label=None,
                amount_findings=0,
                antlr_report=[],
                antlr_features={},
                repository=RepositoryRead.model_validate(repository),
                security_status="VALIDATION_ERROR",
                message="The analysis report format was invalid.",
            )

    def _read_reports_from_db(self, hashes: List[str]):
        """
        Query the database to fetch reports by their hashes.

        Args:
            hashes (List[str]): List of file hashes.

        Returns:
            List[Report]: A list of Report objects.
        """
        if not hashes:
            return []
        try:
            statement = select(Report).where(Report.file_hash.in_(hashes))  # type: ignore
            full_reports = self.session.exec(statement).all()
            return full_reports
        except SQLAlchemyError as e:
            logger.error(f"Database error while reading reports: {e}")
            return []
    def _read_repository_from_db(self, repository_create: RepositoryCreate) -> Repository | None:
        """
        Query the database to fetch a repository by its hash.

        Args:
            repo_hash (str): The file hash of the repository.

        Returns:
            Repository: The Repository object if found, else None.
        """
        statement = select(Repository).where(Repository.url == repository_create.url)
        try:
            repo = self.session.exec(statement).first()
            return repo
        except SQLAlchemyError as e:
            logger.error(f"Database error while reading repository: {e}")
            return None
        
    def process_and_respond(self, raw_reports: List[Dict[str, Any]], repository_create: RepositoryCreate, benign: bool = True, to_predict: bool = False,) -> List[ReportReadWithRepository]:
        """
        Process a list of reports: store successful ones in the DB and
        build a response list for ALL reports.

        Args:
            raw_reports (List[Dict[str, Any]]): The raw reports to process.
            repository (Repository): The associated repository object.
            benign (bool, optional): Used for training data population. Defaults to True.
            to_predict (bool, optional): Used for ML prediction. Defaults to False.

        Returns:
            List[ReportReadWithRepository]: Processed response objects.
        """
        
        try:
            existing_repo = self._read_repository_from_db(repository_create)
            if existing_repo:
                repository = existing_repo
                if repository_create.commit_hash:
                    logger.info(f"Updating existing repository '{repository.url}' with new commit hash.")
                    repository.commit_hash = repository_create.commit_hash
                else:
                    repository.commit_hash = "main"
            else:
                repository = Repository(**repository_create.model_dump()) 
                logger.info(f"Saving new repository '{repository.url}' to the database.")

            self.session.add(repository)
            self.session.commit()
            self.session.refresh(repository)
            logger.info(f"Repository '{repository.url}' saved with ID {repository.id}.")

        except SQLAlchemyError as e:
            logger.error(f"Database error while saving repository: {e}")
            self.session.rollback()
            error_response = self._build_response_from_raw(
                {
                    "status": "DATABASE_ERROR",
                    "message": f"Could not save repository: {e}",
                },
                RepositoryRead.model_validate(repository_create)  # type: ignore
            )
            return [error_response] * len(raw_reports)


        successful_raw_reports = [r for r in raw_reports if r.get("status") == "SUCCESS" and r.get("original_code") not in ["", None, " ", "utf-8"]]
        try:
            if successful_raw_reports:
                hashes = [generate_sha256_hash(r.get("original_code", "")) for r in successful_raw_reports]
                existing_reports_map = {r.file_hash: r for r in self._read_reports_from_db(hashes)}
                logger.info(f"Saving/Updating {len(successful_raw_reports)} reports in the database.")

                for i, raw_report in enumerate(successful_raw_reports):
                    file_hash = hashes[i]
                    if file_hash in existing_reports_map:
                        db_report = existing_reports_map[file_hash]  # Update
                        logger.info(f"Updating existing report in DB. {db_report.file_name} already has repository ID: {db_report.repository_id} and hash: {db_report.file_hash}")
                    else:
                        db_report = Report(repository=repository)   # type: ignore # Create new

                    # Populate/Update fields
                    db_report.file_hash = file_hash
                    db_report.file_name = raw_report.get("file_path", "").split(os.sep)[-1][:255]
                    db_report.source_code = raw_report.get("original_code", "")
                    db_report.language = raw_report.get("language", "unknown")
                    if to_predict:
                        # Future ML logic
                        pass
                    elif benign:
                        db_report.label = 0
                    else:
                        db_report.label = 1

                    db_report.amount_findings = raw_report.get("amount_findings", 0)
                    db_report.antlr_report = raw_report.get("static_findings", [])  # Save findings
                    db_report.antlr_features = self._extract_ml_features(raw_report)
                    db_report.codebert_embedding = list(
                        get_code_embedding(
                            raw_report.get("original_code", ""),
                            self.codebert_model,
                            self.codebert_tokenizer,
                        )
                    )
                    db_report.analysis_date = datetime.datetime.utcnow()
                    self.session.add(db_report)
                self.session.commit()
                logger.info("Reports successfully saved/updated.")

            # --- Response building for ALL reports ---
            final_response: List[ReportReadWithRepository] = []

            all_successful_hashes = [generate_sha256_hash(r.get("original_code", "")) for r in successful_raw_reports]
            if all_successful_hashes:
                successful_db_reports_map = {r.file_hash: r for r in self._read_reports_from_db(all_successful_hashes)}
            else:
                successful_db_reports_map = {}

            for raw_report in raw_reports:
                if raw_report.get("status") == "SUCCESS":
                    report_hash = generate_sha256_hash(raw_report.get("original_code", ""))
                    db_object = successful_db_reports_map.get(report_hash)
                    if db_object:
                        response_model = ReportReadWithRepository.model_validate(db_object)
                        if db_object.label == 0:
                            response_model.security_status = ("BENIGN")  # or PENDING_ML_ANALYSIS
                            response_model.message = ("Static analysis completed and stored in the database. The file is considered benign.")
                        else:
                            response_model.security_status = "MALICIOUS"
                            response_model.message = ("Static analysis completed and stored in the database. The file is considered malicious.")
                        final_response.append(response_model)
                else:

                    final_response.append(self._build_response_from_raw(raw_report, repository))

            return final_response

        except SQLAlchemyError as e:
            logger.error(f"Database error in process_and_respond: {e}")
            self.session.rollback()
            error_response = self._build_response_from_raw(
                {
                    "status": "DATABASE_ERROR",
                    "message": f"Could not save reports: {e}",
                },
                repository,
            )
            return [error_response] * len(raw_reports)
        except Exception as e:
            logger.error(f"Unexpected error in process_and_respond: {e}")
            self.session.rollback()
            error_response = self._build_response_from_raw(
                {
                    "status": "PROCESSING_ERROR",
                    "message": f"Unexpected error during processing: {e}",
                },
                repository,
            )
            return [error_response] * len(raw_reports)


if __name__ == "__main__":
    from db.sintetic_data import sintetic_data
    from db.database import get_session, create_db_and_tables

    create_db_and_tables()
    print("Testing ReportService")

    report_data = sintetic_data[:]
    repository_http_request = RepositoryCreate(
        url="https://github.com/JuanSebastianFernandez/GenSQLDatasets-2",
        #commit_hash="asdad4587asfasf565asfasf587qwe56646664"
    )

    with next(get_session()) as session:
        manager = ReportService(session)
        all_reports = manager.process_and_respond(report_data, repository_http_request)
        for report in all_reports:
            print(report.model_dump())
            print("-" * 80)
        print("\nTotal reports processed:", len(all_reports))
