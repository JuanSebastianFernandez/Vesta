from __future__ import annotations

import datetime
import uuid
from typing import Any

from sqlmodel import Session, select

from app.models.containment_models import ContainmentActionAudit, DeployHoneypotRequest, IsolateNodeRequest
from app.models.defense_models import DefenseLogEvent, DefenseLogEventCreate, ThreatAlert
from app.models.demo_models import DemoScenarioRunRequest
from app.models.prevention_models import AnalysisJob
from app.services.containment_service import ContainmentService
from app.services.demo_runtime_service import DemoRuntimeService
from app.services.network_analyzer_service import NetworkAnalyzerService


class DemoScenarioService:
    """
    Reproducible demo scenarios that emit defense telemetry and optionally
    execute containment against the Docker lab runtime.
    """

    def __init__(self, session: Session):
        self.session = session
        self.runtime_service = DemoRuntimeService(session=session)
        self.defense_service = NetworkAnalyzerService(session=session)
        self.containment_service = ContainmentService(session=session, runtime_service=self.runtime_service)

    def list_runtime_assets(self) -> dict[str, Any]:
        return self.runtime_service.list_assets().model_dump(mode="json")

    def build_timeline(self, limit: int = 50) -> dict[str, Any]:
        items: list[dict[str, Any]] = []

        for job in self.session.exec(select(AnalysisJob).order_by(AnalysisJob.created_at.desc()).limit(limit)).all():
            items.append(
                {
                    "kind": "analysis_job",
                    "time": job.created_at.isoformat() + "Z" if job.created_at else None,
                    "title": f"Analysis job {job.status}",
                    "details": {
                        "job_id": job.id,
                        "repository_name": job.repository_name,
                        "status": job.status,
                        "trigger_source": job.trigger_source,
                    },
                }
            )

        for event in self.session.exec(
            select(DefenseLogEvent).order_by(DefenseLogEvent.event_time.desc()).limit(limit)
        ).all():
            items.append(
                {
                    "kind": "defense_event",
                    "time": event.event_time.isoformat() + "Z" if event.event_time else None,
                    "title": event.event_type,
                    "details": {
                        "event_id": event.id,
                        "source_system": event.source_system,
                        "host_id": event.host_id,
                        "message": event.message[:160],
                    },
                }
            )

        for alert in self.session.exec(select(ThreatAlert).order_by(ThreatAlert.created_at.desc()).limit(limit)).all():
            items.append(
                {
                    "kind": "alert",
                    "time": alert.created_at.isoformat() + "Z" if alert.created_at else None,
                    "title": alert.rule_code,
                    "details": {
                        "alert_id": alert.id,
                        "severity": alert.severity,
                        "score": alert.score,
                        "status": alert.status,
                        "summary": alert.summary[:180],
                    },
                }
            )

        for action in self.session.exec(
            select(ContainmentActionAudit).order_by(ContainmentActionAudit.requested_at.desc()).limit(limit)
        ).all():
            items.append(
                {
                    "kind": "containment_action",
                    "time": action.requested_at.isoformat() + "Z" if action.requested_at else None,
                    "title": action.action_type,
                    "details": {
                        "action_id": action.id,
                        "status": action.status,
                        "execution_mode": action.execution_mode,
                        "target_value": action.target_value,
                    },
                }
            )

        items_sorted = sorted(
            [item for item in items if item.get("time")],
            key=lambda item: item["time"],
            reverse=True,
        )[:limit]
        return {
            "runtime": self.list_runtime_assets(),
            "items": items_sorted,
        }

    def run_scenario(self, scenario_code: str, payload: DemoScenarioRunRequest) -> dict[str, Any]:
        normalized = (scenario_code or "").strip().lower()
        builder = {
            "brute-force": self._scenario_brute_force,
            "exfiltration": self._scenario_exfiltration,
            "suspicious-command": self._scenario_suspicious_command,
            "beaconing": self._scenario_beaconing,
            "ransomware": self._scenario_ransomware,
        }.get(normalized)
        if builder is None:
            raise ValueError(f"Unsupported demo scenario '{scenario_code}'.")

        scenario_run_id = f"{normalized}-{uuid.uuid4().hex[:12]}"
        responses = self.defense_service.ingest_events_batch(builder(payload, scenario_run_id))
        containment_actions: list[dict[str, Any]] = []
        if payload.auto_contain:
            containment_actions = self._run_follow_up_containment(
                scenario_code=normalized,
                requested_by=payload.requested_by,
                repository_id=payload.repository_id,
                responses=responses,
            )

        return {
            "scenario_code": normalized,
            "scenario_run_id": scenario_run_id,
            "events_ingested": len(responses),
            "alerts_triggered": sum(len(item.triggered_alerts) for item in responses),
            "duplicate_events": sum(1 for item in responses if item.duplicate_event),
            "recommended_actions": [item.action_recommended for item in responses],
            "containment_actions": containment_actions,
            "runtime": self.list_runtime_assets(),
            "timeline": self.build_timeline(limit=20)["items"],
        }

    def _scenario_event_id(self, scenario_run_id: str, event_suffix: str) -> str:
        return f"{scenario_run_id}-{event_suffix}"

    def _run_follow_up_containment(
        self,
        *,
        scenario_code: str,
        requested_by: str,
        repository_id: int | None,
        responses: list[Any],
    ) -> list[dict[str, Any]]:
        actions: list[dict[str, Any]] = []
        max_score = 0.0
        source_alert_id: int | None = None
        for response in responses:
            for alert in response.triggered_alerts:
                max_score = max(max_score, float(alert.score or 0.0))
                source_alert_id = alert.id or source_alert_id

        if scenario_code in {"exfiltration", "ransomware", "beaconing"} and max_score >= 65.0:
            try:
                isolate_response = self.containment_service.isolate_node(
                    IsolateNodeRequest(
                        repository_id=repository_id,
                        source_alert_id=source_alert_id,
                        correlation_id=f"demo-{scenario_code}",
                        reason=f"Demo scenario '{scenario_code}' exceeded containment threshold.",
                        requested_by=requested_by,
                        dry_run=False,
                        host_id=self.runtime_service.smartgrid_host_id,
                        network_segment="demo_prod",
                        quarantine_policy="demo-quarantine",
                    )
                )
                actions.append(isolate_response.model_dump(mode="json"))
            except Exception as exc:  # noqa: BLE001
                actions.append(
                    {
                        "action_type": "ISOLATE_NODE",
                        "status": "FAILED",
                        "execution_mode": "DEMO_DOCKER",
                        "target_value": self.runtime_service.smartgrid_host_id,
                        "message": str(exc),
                    }
                )

        if scenario_code in {"beaconing", "ransomware"} and max_score >= 75.0:
            try:
                honeypot_response = self.containment_service.deploy_honeypot(
                    DeployHoneypotRequest(
                        repository_id=repository_id,
                        source_alert_id=source_alert_id,
                        correlation_id=f"demo-honeypot-{scenario_code}",
                        reason=f"Deploy deception asset after '{scenario_code}' scenario.",
                        requested_by=requested_by,
                        dry_run=False,
                        decoy_target="smartgrid-decoy",
                        honeypot_profile="COWRIE_SSH",
                        ttl_minutes=120,
                        network_zone="demo_deception",
                    )
                )
                actions.append(honeypot_response.model_dump(mode="json"))
            except Exception as exc:  # noqa: BLE001
                actions.append(
                    {
                        "action_type": "DEPLOY_HONEYPOT",
                        "status": "FAILED",
                        "execution_mode": "DEMO_DOCKER",
                        "target_value": "smartgrid-decoy",
                        "message": str(exc),
                    }
                )

        return actions

    def _scenario_brute_force(self, payload: DemoScenarioRunRequest, scenario_run_id: str) -> list[DefenseLogEventCreate]:
        now = datetime.datetime.utcnow()
        return [
            DefenseLogEventCreate(
                repository_id=payload.repository_id,
                source_system="DEMO_ATTACKER",
                source_ip="172.28.0.20",
                host_id="smartgrid-app",
                user_id="operator",
                event_type="AUTH_FAILURE",
                severity="MEDIUM",
                message="failed login for user operator",
                event_time=now + datetime.timedelta(seconds=index),
                event_context={"scenario": "brute-force"},
                raw_payload={"event_id": self._scenario_event_id(scenario_run_id, f"bf-{index}")},
            )
            for index in range(1, 8)
        ]

    def _scenario_exfiltration(self, payload: DemoScenarioRunRequest, scenario_run_id: str) -> list[DefenseLogEventCreate]:
        now = datetime.datetime.utcnow()
        destinations = ["185.10.10.10", "185.10.10.11", "185.10.10.10"]
        events: list[DefenseLogEventCreate] = []
        for index, destination in enumerate(destinations, start=1):
            events.append(
                DefenseLogEventCreate(
                    repository_id=payload.repository_id,
                    source_system="SMARTGRID_APP",
                    source_ip="172.28.0.10",
                    host_id="smartgrid-app",
                    user_id="svc-grid",
                    event_type="DATA_TRANSFER",
                    severity="HIGH",
                    message=f"unexpected outbound transfer to {destination}",
                    event_time=now + datetime.timedelta(seconds=index),
                    event_context={
                        "scenario": "exfiltration",
                        "destination_ip": destination,
                        "bytes_out": 65000000,
                    },
                    raw_payload={"event_id": self._scenario_event_id(scenario_run_id, f"exfil-{index}")},
                )
            )
        return events

    def _scenario_suspicious_command(self, payload: DemoScenarioRunRequest, scenario_run_id: str) -> list[DefenseLogEventCreate]:
        now = datetime.datetime.utcnow()
        commands = [
            "powershell encoded command detected",
            "download payload and make executable",
            "disable defender via script",
        ]
        flags = [
            {"suspicious_command": True},
            {"suspicious_command": True, "remote_exec": True},
            {"defense_evasion": True},
        ]
        return [
            DefenseLogEventCreate(
                repository_id=payload.repository_id,
                source_system="EDR",
                source_ip="172.28.0.10",
                host_id="smartgrid-app",
                user_id="svc-grid",
                event_type="COMMAND_EXECUTION",
                severity="HIGH",
                message=commands[index],
                event_time=now + datetime.timedelta(seconds=index),
                event_context={"scenario": "suspicious-command", **flags[index]},
                raw_payload={"event_id": self._scenario_event_id(scenario_run_id, f"cmd-{index}")},
            )
            for index in range(len(commands))
        ]

    def _scenario_beaconing(self, payload: DemoScenarioRunRequest, scenario_run_id: str) -> list[DefenseLogEventCreate]:
        now = datetime.datetime.utcnow()
        return [
            DefenseLogEventCreate(
                repository_id=payload.repository_id,
                source_system="SMARTGRID_APP",
                source_ip="172.28.0.10",
                host_id="smartgrid-app",
                user_id="svc-grid",
                event_type="NETWORK_CONNECTION",
                severity="HIGH",
                message="periodic connect callback to C2 endpoint",
                event_time=now + datetime.timedelta(seconds=index * 20),
                event_context={
                    "scenario": "beaconing",
                    "destination_ip": "185.99.1.77",
                    "beaconing": True,
                    "periodic_connection": True,
                    "bytes_out": 8000,
                },
                raw_payload={"event_id": self._scenario_event_id(scenario_run_id, f"beacon-{index}")},
            )
            for index in range(1, 6)
        ]

    def _scenario_ransomware(self, payload: DemoScenarioRunRequest, scenario_run_id: str) -> list[DefenseLogEventCreate]:
        now = datetime.datetime.utcnow()
        file_paths = [
            "/data/customers/file1.locked",
            "/data/customers/file2.locked",
            "/data/customers/file3.locked",
            "/data/customers/file4.locked",
        ]
        return [
            DefenseLogEventCreate(
                repository_id=payload.repository_id,
                source_system="SMARTGRID_APP",
                source_ip="172.28.0.10",
                host_id="smartgrid-app",
                user_id="svc-grid",
                event_type="FILE_OPERATION",
                severity="CRITICAL",
                message=f"encrypt and delete backups for {file_path}",
                event_time=now + datetime.timedelta(seconds=index),
                event_context={
                    "scenario": "ransomware",
                    "file_path": file_path,
                    "encryption_activity": True,
                    "backup_deletion": True,
                    "bulk_file_changes": True,
                },
                raw_payload={"event_id": self._scenario_event_id(scenario_run_id, f"ransom-{index}")},
            )
            for index, file_path in enumerate(file_paths, start=1)
        ]
