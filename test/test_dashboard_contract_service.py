import datetime
import unittest
from types import SimpleNamespace

from app.services.dashboard_contract_service import DashboardContractService


class TestDashboardContractService(unittest.TestCase):
    def setUp(self):
        self.service = DashboardContractService()

    def test_build_contract_has_expected_top_level_fields(self):
        job = SimpleNamespace(
            id="job-123",
            repository_url="https://github.com/example/repo.git",
            repository_name="repo",
            commit_hash="abc123",
            trigger_source="MANUAL",
            status="DONE",
            created_at=datetime.datetime(2026, 2, 28, 20, 0, 0),
            started_at=datetime.datetime(2026, 2, 28, 20, 0, 1),
            finished_at=datetime.datetime(2026, 2, 28, 20, 0, 4),
        )
        reports = [
            {
                "file_hash": "h1",
                "file_name": "a.py",
                "language": "Python",
                "security_status": "BENIGN",
                "label": 0,
                "prediction_probability": 0.91,
                "risk_score": 30.0,
                "amount_findings": 0,
                "prediction_source": "ML_ANTLR_HYBRID",
                "message": "ok",
                "repository": {"id": 10, "url": "https://github.com/example/repo.git"},
            }
        ]
        summary = {"total_reports": 1, "status_counts": {"BENIGN": 1}}
        dast_result = {"status": "SUCCESS", "network_capture": {"status": "NO_CAPTURE_OUTPUT", "metrics": {}}}
        unified_risk = {"risk_score": 22.1, "risk_level": "LOW", "formula_version": "v1.0.0"}

        payload = self.service.build_job_result_contract(
            job=job,
            response_reports=reports,
            summary=summary,
            dast_result=dast_result,
            unified_risk=unified_risk,
        )

        self.assertEqual(payload["schema_version"], "1.0.0")
        self.assertIn("repository", payload)
        self.assertIn("analysis", payload)
        self.assertIn("summary", payload)
        self.assertIn("totals", payload)
        self.assertIn("risk", payload)
        self.assertIn("dast", payload)
        self.assertIn("files", payload)
        self.assertIn("reports", payload)

    def test_totals_and_findings_projection(self):
        job = SimpleNamespace(
            id="job-xyz",
            repository_url="https://github.com/example/repo.git",
            repository_name="repo",
            commit_hash="main",
            trigger_source="MANUAL",
            status="DONE",
            created_at=None,
            started_at=None,
            finished_at=None,
        )
        reports = [
            {"file_name": "a.py", "amount_findings": 0, "security_status": "BENIGN"},
            {"file_name": "b.py", "amount_findings": 3, "security_status": "SUSPICIOUS"},
        ]
        summary = {"total_reports": 2, "status_counts": {"BENIGN": 1, "SUSPICIOUS": 1}}

        payload = self.service.build_job_result_contract(
            job=job,
            response_reports=reports,
            summary=summary,
            dast_result={},
            unified_risk={},
        )

        self.assertEqual(payload["totals"]["files_analyzed"], 2)
        self.assertEqual(payload["totals"]["files_with_findings"], 1)
        self.assertEqual(payload["totals"]["findings_total"], 3)
        self.assertEqual(payload["files"][1]["findings_total"], 3)
        self.assertTrue(payload["files"][1]["has_findings"])


if __name__ == "__main__":
    unittest.main()

