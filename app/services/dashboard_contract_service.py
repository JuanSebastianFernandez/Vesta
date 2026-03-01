from __future__ import annotations

import datetime
from typing import Any


class DashboardContractService:
    """
    Builds and validates a stable dashboard payload contract.
    """

    SCHEMA_VERSION = "1.0.0"
    REQUIRED_TOP_LEVEL_KEYS = {
        "schema_version",
        "repository",
        "analysis",
        "summary",
        "totals",
        "risk",
        "dast",
        "files",
        "reports",
    }

    def _extract_field(self, item: Any, field_name: str, default: Any = None) -> Any:
        if isinstance(item, dict):
            return item.get(field_name, default)
        return getattr(item, field_name, default)

    def _to_float(self, value: Any, default: float = 0.0) -> float:
        try:
            if value is None:
                return default
            return float(value)
        except (TypeError, ValueError):
            return default

    def _to_int(self, value: Any, default: int = 0) -> int:
        try:
            if value is None:
                return default
            return int(value)
        except (TypeError, ValueError):
            return default

    def _to_iso(self, value: Any) -> str | None:
        if value is None:
            return None
        if isinstance(value, datetime.datetime):
            return value.isoformat() + "Z"
        return str(value)

    def _compact_file_report(self, item: Any) -> dict[str, Any]:
        amount_findings = self._to_int(self._extract_field(item, "amount_findings", 0), 0)
        return {
            "file_hash": self._extract_field(item, "file_hash"),
            "file_name": self._extract_field(item, "file_name"),
            "language": self._extract_field(item, "language"),
            "security_status": self._extract_field(item, "security_status"),
            "label": self._extract_field(item, "label"),
            "prediction_probability": self._extract_field(item, "prediction_probability"),
            "risk_score": self._extract_field(item, "risk_score"),
            "amount_findings": amount_findings,
            "prediction_source": self._extract_field(item, "prediction_source"),
            "message": self._extract_field(item, "message"),
            "findings_total": amount_findings,
            "has_findings": amount_findings > 0,
        }

    def _extract_repository_id(self, reports: list[Any]) -> int | None:
        for item in reports:
            repository_obj = None
            if isinstance(item, dict):
                repository_obj = item.get("repository")
            else:
                repository_obj = getattr(item, "repository", None)

            if isinstance(repository_obj, dict):
                repo_id = repository_obj.get("id")
            else:
                repo_id = getattr(repository_obj, "id", None) if repository_obj is not None else None

            try:
                if repo_id is not None:
                    return int(repo_id)
            except (TypeError, ValueError):
                continue
        return None

    def build_job_result_contract(
        self,
        *,
        job: Any,
        response_reports: list[Any],
        summary: dict[str, Any],
        dast_result: dict[str, Any] | None,
        unified_risk: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """
        Build payload contract and validate it against a stable schema.
        """
        compact_reports = [self._compact_file_report(item) for item in response_reports]
        findings_total = sum(self._to_int(item.get("amount_findings"), 0) for item in compact_reports)
        files_with_findings = sum(1 for item in compact_reports if self._to_int(item.get("amount_findings"), 0) > 0)

        started_at = self._extract_field(job, "started_at")
        finished_at = self._extract_field(job, "finished_at")
        duration_seconds: float | None = None
        if isinstance(started_at, datetime.datetime) and isinstance(finished_at, datetime.datetime):
            duration_seconds = round((finished_at - started_at).total_seconds(), 3)

        payload = {
            "schema_version": self.SCHEMA_VERSION,
            "repository": {
                "id": self._extract_repository_id(response_reports),
                "url": str(self._extract_field(job, "repository_url", "")),
                "name": str(self._extract_field(job, "repository_name", "")),
                "commit_hash": self._extract_field(job, "commit_hash"),
            },
            "analysis": {
                "job_id": str(self._extract_field(job, "id", "")),
                "trigger_source": str(self._extract_field(job, "trigger_source", "UNKNOWN")),
                "status": str(self._extract_field(job, "status", "UNKNOWN")),
                "created_at": self._to_iso(self._extract_field(job, "created_at")),
                "started_at": self._to_iso(started_at),
                "finished_at": self._to_iso(finished_at),
                "duration_seconds": duration_seconds,
            },
            "summary": {
                "total_reports": self._to_int(summary.get("total_reports", len(compact_reports)), len(compact_reports)),
                "status_counts": summary.get("status_counts", {}),
            },
            "totals": {
                "files_analyzed": len(compact_reports),
                "files_with_findings": files_with_findings,
                "findings_total": findings_total,
            },
            "risk": unified_risk or {},
            "dast": dast_result or {},
            "files": compact_reports,
            "reports": compact_reports,
        }

        self._validate_payload(payload)
        return payload

    def _validate_payload(self, payload: dict[str, Any]) -> None:
        """
        Lightweight schema validation so the contract remains explicit and stable
        without requiring external validator dependencies at runtime.
        """
        missing = [k for k in self.REQUIRED_TOP_LEVEL_KEYS if k not in payload]
        if missing:
            raise ValueError(f"Dashboard contract missing required keys: {missing}")

        if payload.get("schema_version") != self.SCHEMA_VERSION:
            raise ValueError(
                f"Dashboard contract schema_version must be '{self.SCHEMA_VERSION}'."
            )

        if not isinstance(payload.get("repository"), dict):
            raise ValueError("Dashboard contract 'repository' must be an object.")
        if not isinstance(payload.get("analysis"), dict):
            raise ValueError("Dashboard contract 'analysis' must be an object.")
        if not isinstance(payload.get("summary"), dict):
            raise ValueError("Dashboard contract 'summary' must be an object.")
        if not isinstance(payload.get("totals"), dict):
            raise ValueError("Dashboard contract 'totals' must be an object.")
        if not isinstance(payload.get("risk"), dict):
            raise ValueError("Dashboard contract 'risk' must be an object.")
        if not isinstance(payload.get("dast"), dict):
            raise ValueError("Dashboard contract 'dast' must be an object.")
        if not isinstance(payload.get("files"), list):
            raise ValueError("Dashboard contract 'files' must be an array.")
        if not isinstance(payload.get("reports"), list):
            raise ValueError("Dashboard contract 'reports' must be an array.")
