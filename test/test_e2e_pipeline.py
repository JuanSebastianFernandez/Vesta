import datetime
import hashlib
import hmac
import json
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

import app.main as main_app
from app.api.v1.endpoints import defense, prevention
from app.core.config import settings
from app.models.defense_models import DefenseIngestResponse, DefenseLogEventRead, ThreatAlertRead
from app.models.prevention_models import AnalysisJob


class _FakeSession:
    def __init__(self):
        self.jobs: dict[str, AnalysisJob] = {}

    def add(self, obj):
        if isinstance(obj, AnalysisJob):
            self.jobs[obj.id] = obj

    def commit(self):
        return None

    def refresh(self, _obj):
        return None

    def rollback(self):
        return None

    def get(self, model, obj_id):
        if model is AnalysisJob:
            return self.jobs.get(obj_id)
        return None


class _FakeSessionContext:
    def __init__(self, fake_session):
        self._fake_session = fake_session

    def __enter__(self):
        return self._fake_session

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False


class _FakeReportService:
    def __init__(self, session):
        self._session = session

    def process_and_respond(self, raw_reports, repository_create):
        _ = raw_reports
        _ = repository_create
        return [
            {
                "file_hash": "benign-hash",
                "file_name": "safe.py",
                "language": "Python",
                "label": 0,
                "prediction_probability": 0.93,
                "risk_score": 18.4,
                "prediction_source": "ML_ANTLR_HYBRID",
                "amount_findings": 0,
                "security_status": "BENIGN",
                "message": "benign",
                "repository": {"id": 7, "url": "https://github.com/org/repo.git"},
            },
            {
                "file_hash": "malicious-hash",
                "file_name": "danger.py",
                "language": "Python",
                "label": 1,
                "prediction_probability": 0.99,
                "risk_score": 98.0,
                "prediction_source": "ML_ANTLR_HYBRID",
                "amount_findings": 12,
                "security_status": "MALICIOUS",
                "message": "malicious",
                "repository": {"id": 7, "url": "https://github.com/org/repo.git"},
            },
        ]


class _FakeDefenseService:
    def ingest_event(self, payload, auto_analyze, auto_close_stale_alerts, ttl_minutes, include_critical_stale):
        _ = payload
        _ = auto_analyze
        _ = auto_close_stale_alerts
        _ = ttl_minutes
        _ = include_critical_stale

        now = datetime.datetime.utcnow()
        event = DefenseLogEventRead(
            id=101,
            repository_id=7,
            source_system="EDR",
            event_external_id="evt-101",
            source_ip="10.10.10.5",
            host_id="host-a",
            user_id="alice",
            event_type="COMMAND_EXECUTION",
            severity="HIGH",
            message="encoded command execution observed",
            event_time=now,
            event_context={"suspicious_command": True},
            raw_payload={"event_id": "evt-101"},
            ingested_at=now,
        )
        alert = ThreatAlertRead(
            id=9001,
            repository_id=7,
            rule_code="SUSPICIOUS_COMMAND_EXECUTION",
            source_system="EDR",
            source_ip="10.10.10.5",
            host_id="host-a",
            severity="CRITICAL",
            score=94.0,
            confidence=0.98,
            status="OPEN",
            summary="High-confidence suspicious command execution pattern.",
            context_window_start=now - datetime.timedelta(minutes=3),
            context_window_end=now,
            evidence_count=6,
            unique_targets=1,
            evidence={"event_ids": [101]},
            created_at=now,
            updated_at=now,
        )
        return DefenseIngestResponse(
            event=event,
            triggered_alerts=[alert],
            analyzed_rules=5,
            action_recommended="TRIGGER_CONTAINMENT",
            duplicate_event=False,
            duplicate_of_event_id=None,
            containment_trigger={
                "attempted": True,
                "status": "SENT",
                "threshold_score": 65.0,
                "max_alert_score": 94.0,
                "message": "Containment trigger sent successfully.",
                "response": {"accepted": True},
            },
        )


class TestE2EPipeline(unittest.TestCase):
    def setUp(self):
        self.fake_session = _FakeSession()

        def _override_session():
            yield self.fake_session

        self._override_session = _override_session
        main_app.app.dependency_overrides[prevention.get_session] = self._override_session
        main_app.app.dependency_overrides[defense.get_session] = self._override_session

    def tearDown(self):
        main_app.app.dependency_overrides.clear()

    @staticmethod
    def _sign_github_payload(body: bytes) -> str:
        digest = hmac.new(
            settings.GITHUB_WEBHOOK_SECRET.encode("utf-8"),
            body,
            hashlib.sha256,
        ).hexdigest()
        return f"sha256={digest}"

    def test_async_background_runner_builds_full_contract(self):
        job = AnalysisJob(
            repository_url="https://github.com/org/repo.git",
            repository_name="repo",
            commit_hash="abc123",
            trigger_source="WEBHOOK_GITHUB",
            status="PENDING",
        )
        self.fake_session.add(job)

        with (
            patch("app.api.v1.endpoints.prevention.Session", lambda *_args, **_kwargs: _FakeSessionContext(self.fake_session)),
            patch.object(prevention.repo_manager, "process_repository", return_value=[{"file_name": "safe.py"}]),
            patch.object(prevention.repo_manager, "get_repo_path", return_value="C:/fake/repo"),
            patch("app.api.v1.endpoints.prevention.ReportService", _FakeReportService),
            patch.object(
                prevention.dynamic_analysis_service,
                "analyze_repository",
                return_value={
                    "status": "SUCCESS",
                    "network_capture": {
                        "status": "PARSED",
                        "metrics": {
                            "packets_total": 12,
                            "unique_destinations": 2,
                            "unique_destination_ports": 2,
                            "dns_queries_count": 1,
                            "tcp_syn_attempts": 1,
                        },
                    },
                    "container_exit_code": 0,
                },
            ),
        ):
            prevention._run_analysis_job_background(job.id)

        updated = self.fake_session.get(AnalysisJob, job.id)
        self.assertIsNotNone(updated)
        self.assertEqual(updated.status, "DONE")
        self.assertIn("schema_version", updated.result_summary)
        self.assertIn("risk", updated.result_summary)
        self.assertIn("dast", updated.result_summary)
        self.assertIn("summary", updated.result_summary)
        self.assertEqual(updated.result_summary["summary"]["total_reports"], 2)
        self.assertEqual(updated.result_summary["summary"]["status_counts"]["MALICIOUS"], 1)
        self.assertGreaterEqual(updated.result_summary["risk"]["risk_score"], 0.0)

    def test_webhook_push_schedules_job_and_exposes_result(self):
        def _fake_background(job_id: str) -> None:
            job = self.fake_session.get(AnalysisJob, job_id)
            if not job:
                return
            now = datetime.datetime.utcnow()
            job.status = "DONE"
            job.started_at = now - datetime.timedelta(seconds=2)
            job.finished_at = now
            job.result_summary = {
                "schema_version": "1.0.0",
                "summary": {"total_reports": 2},
                "risk": {"risk_score": 42.5, "risk_level": "MEDIUM"},
            }
            self.fake_session.add(job)
            self.fake_session.commit()

        payload = {
            "repository": {
                "clone_url": "https://github.com/org/repo.git",
                "name": "repo",
            },
            "head_commit": {"id": "abc123"},
            "after": "abc123",
        }

        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers = {
            "X-GitHub-Event": "push",
            "X-GitHub-Delivery": "delivery-1",
            "X-Hub-Signature-256": self._sign_github_payload(body),
            "Content-Type": "application/json",
        }

        with (
            patch("app.main.create_db_and_tables", lambda: None),
            patch("app.api.v1.endpoints.prevention._run_analysis_job_background", _fake_background),
            TestClient(main_app.app) as client,
        ):
            response = client.post("/prevention/webhooks/github", content=body, headers=headers)
            self.assertEqual(response.status_code, 202)
            response_data = response.json()
            self.assertEqual(response_data["status"], "ACCEPTED")
            job_id = response_data["job_id"]

            status_resp = client.get(f"/prevention/jobs/{job_id}")
            self.assertEqual(status_resp.status_code, 200)
            self.assertEqual(status_resp.json()["status"], "DONE")

            result_resp = client.get(f"/prevention/jobs/{job_id}/result")
            self.assertEqual(result_resp.status_code, 200)
            result_payload = result_resp.json()
            self.assertEqual(result_payload["status"], "DONE")
            self.assertEqual(result_payload["result"]["schema_version"], "1.0.0")
            self.assertIn("risk", result_payload["result"])

    def test_defense_events_endpoint_returns_alert_and_trigger(self):
        payload = {
            "repository_id": 7,
            "source_system": "EDR",
            "source_ip": "10.10.10.5",
            "host_id": "host-a",
            "user_id": "alice",
            "event_type": "COMMAND_EXECUTION",
            "severity": "HIGH",
            "message": "encoded command execution observed",
            "event_context": {"suspicious_command": True},
            "raw_payload": {"event_id": "evt-101"},
        }

        with (
            patch("app.main.create_db_and_tables", lambda: None),
            patch("app.api.v1.endpoints.defense._service", lambda _session: _FakeDefenseService()),
            TestClient(main_app.app) as client,
        ):
            response = client.post("/defense/events", json=payload)
            self.assertEqual(response.status_code, 201)
            data = response.json()
            self.assertEqual(data["action_recommended"], "TRIGGER_CONTAINMENT")
            self.assertEqual(len(data["triggered_alerts"]), 1)
            self.assertEqual(data["containment_trigger"]["status"], "SENT")
            self.assertGreaterEqual(data["containment_trigger"]["max_alert_score"], 90.0)


if __name__ == "__main__":
    unittest.main()
