from __future__ import annotations
import datetime
import ipaddress
from typing import Any

from sqlmodel import Session, select

from app.models.defense_models import (
    DefenseLogEvent,
    DefenseLogEventCreate,
    DefenseIngestResponse,
    ThreatAlert,
    ThreatAlertRead,
    ThreatPatternRule,
    ThreatPatternRuleRead,
)


class NetworkAnalyzerService:
    """
    Active defense service for behavior analysis over log events.
    """

    DEFAULT_RULES: list[dict[str, Any]] = [
        {
            "code": "BRUTE_FORCE_AUTH",
            "name": "Auth Brute Force",
            "description": "Repeated authentication failures from same origin in short window.",
            "severity": "HIGH",
            "weight": 1.0,
            "window_minutes": 10,
            "threshold": 6,
            "min_unique_targets": 1,
            "extra_params": {
                "event_types": ["AUTH_FAILURE", "LOGIN_FAILED", "FAILED_LOGIN", "SSH_AUTH_FAILURE"],
                "keywords": ["failed login", "authentication failed", "invalid password"],
            },
        },
        {
            "code": "LATERAL_MOVEMENT_SCAN",
            "name": "Lateral Movement Scan",
            "description": "Cross-host denied accesses suggesting lateral movement attempts.",
            "severity": "HIGH",
            "weight": 1.1,
            "window_minutes": 15,
            "threshold": 8,
            "min_unique_targets": 3,
            "extra_params": {
                "event_types": ["NETWORK_CONNECTION", "CONNECTION_DENIED", "RDP_AUTH_FAILURE", "SMB_ACCESS"],
                "keywords": ["denied", "refused", "unauthorized", "timeout"],
            },
        },
        {
            "code": "SUSPICIOUS_COMMAND_EXECUTION",
            "name": "Suspicious Command Execution",
            "description": "Execution of command patterns associated with malware staging/persistence.",
            "severity": "HIGH",
            "weight": 1.2,
            "window_minutes": 20,
            "threshold": 2,
            "min_unique_targets": 1,
            "extra_params": {
                "event_types": ["COMMAND_EXECUTION", "PROCESS_CREATE", "SCRIPT_EXECUTION"],
                "keywords": [
                    "encoded command",
                    "base64 decode",
                    "download payload",
                    "delete backup snapshot",
                    "change boot config",
                    "make executable",
                ],
            },
        },
        {
            "code": "DATA_EXFILTRATION_PATTERN",
            "name": "Potential Data Exfiltration",
            "description": "Unusual outbound transfer volume and destination spread.",
            "severity": "CRITICAL",
            "weight": 1.3,
            "window_minutes": 30,
            "threshold": 3,
            "min_unique_targets": 2,
            "extra_params": {
                "event_types": ["DATA_TRANSFER", "NETWORK_CONNECTION"],
                "bytes_out_threshold": 50000000,
                "destination_field": "destination_ip",
            },
        },
        {
            "code": "RANSOMWARE_BEHAVIORAL_PATTERN",
            "name": "Ransomware Behavioral Pattern",
            "description": "File-encryption related behavior with destructive backup actions.",
            "severity": "CRITICAL",
            "weight": 1.4,
            "window_minutes": 20,
            "threshold": 4,
            "min_unique_targets": 2,
            "extra_params": {
                "event_types": ["FILE_OPERATION", "COMMAND_EXECUTION", "PROCESS_CREATE"],
                "keywords": [
                    ".locked",
                    ".encrypted",
                    "encrypt",
                    "ransom",
                    "shadow copy",
                    "delete backups",
                ],
                "file_field": "file_path",
            },
        },
    ]

    def __init__(self, session: Session):
        self.session = session

    def ensure_default_rules(self, sync_existing: bool = False) -> list[ThreatPatternRule]:
        created_or_updated: list[ThreatPatternRule] = []
        existing = {r.code: r for r in self.session.exec(select(ThreatPatternRule)).all()}
        if existing and not sync_existing:
            return list(existing.values())

        now = datetime.datetime.utcnow()

        for rule_data in self.DEFAULT_RULES:
            code = str(rule_data["code"])
            if code in existing:
                rule = existing[code]
                if not sync_existing:
                    created_or_updated.append(rule)
                    continue
                rule.name = rule_data["name"]
                rule.description = rule_data["description"]
                rule.severity = rule_data["severity"]
                rule.weight = float(rule_data["weight"])
                rule.window_minutes = int(rule_data["window_minutes"])
                rule.threshold = int(rule_data["threshold"])
                rule.min_unique_targets = int(rule_data["min_unique_targets"])
                rule.extra_params = dict(rule_data.get("extra_params", {}))
                rule.updated_at = now
            else:
                rule = ThreatPatternRule(
                    code=code,
                    name=rule_data["name"],
                    description=rule_data["description"],
                    severity=rule_data["severity"],
                    weight=float(rule_data["weight"]),
                    window_minutes=int(rule_data["window_minutes"]),
                    threshold=int(rule_data["threshold"]),
                    min_unique_targets=int(rule_data["min_unique_targets"]),
                    extra_params=dict(rule_data.get("extra_params", {})),
                    created_at=now,
                    updated_at=now,
                )
                self.session.add(rule)
            created_or_updated.append(rule)

        self.session.commit()
        for rule in created_or_updated:
            self.session.refresh(rule)
        return created_or_updated

    def _store_event(self, payload: DefenseLogEventCreate) -> DefenseLogEvent:
        event = DefenseLogEvent(**payload.model_dump())
        self.session.add(event)
        self.session.commit()
        self.session.refresh(event)
        return event

    def ingest_event(
        self,
        payload: DefenseLogEventCreate,
        auto_analyze: bool = True,
        ensure_rules: bool = True,
    ) -> DefenseIngestResponse:
        if ensure_rules:
            self.ensure_default_rules()

        event = self._store_event(payload)

        triggered_alerts: list[ThreatAlert] = []
        analyzed_rules = 0
        if auto_analyze:
            triggered_alerts, analyzed_rules = self.analyze_event_context(event)

        action = self._recommend_action(triggered_alerts)
        return DefenseIngestResponse(
            event=event,
            triggered_alerts=[ThreatAlertRead.model_validate(a) for a in triggered_alerts],
            analyzed_rules=analyzed_rules,
            action_recommended=action,
        )

    def ingest_events_batch(
        self,
        payloads: list[DefenseLogEventCreate],
        auto_analyze: bool = True,
    ) -> list[DefenseIngestResponse]:
        self.ensure_default_rules()
        responses: list[DefenseIngestResponse] = []
        for payload in payloads:
            responses.append(
                self.ingest_event(
                    payload=payload,
                    auto_analyze=auto_analyze,
                    ensure_rules=False,
                )
            )
        return responses

    def analyze_event_context(self, event: DefenseLogEvent) -> tuple[list[ThreatAlert], int]:
        active_rules = list(
            self.session.exec(
                select(ThreatPatternRule).where(ThreatPatternRule.is_active == True)  # noqa: E712
            ).all()
        )
        if not active_rules:
            return [], 0

        alerts: list[ThreatAlert] = []
        for rule in active_rules:
            context_events = self._fetch_context_events(event=event, window_minutes=rule.window_minutes)
            match = self._evaluate_rule(rule=rule, context_events=context_events)
            if not match:
                continue
            alert = self._upsert_alert(event=event, rule=rule, match=match)
            alerts.append(alert)

        self.session.commit()
        for alert in alerts:
            self.session.refresh(alert)
        return alerts, len(active_rules)

    def _fetch_context_events(self, event: DefenseLogEvent, window_minutes: int) -> list[DefenseLogEvent]:
        window_start = event.event_time - datetime.timedelta(minutes=window_minutes)
        stmt = select(DefenseLogEvent).where(
            DefenseLogEvent.source_system == event.source_system,
            DefenseLogEvent.event_time >= window_start,
            DefenseLogEvent.event_time <= event.event_time,
        )
        all_events = list(self.session.exec(stmt).all())
        if not all_events:
            return []

        filtered: list[DefenseLogEvent] = []
        for item in all_events:
            if event.source_ip and item.source_ip == event.source_ip:
                filtered.append(item)
                continue
            if event.host_id and item.host_id == event.host_id:
                filtered.append(item)
                continue
            if event.user_id and item.user_id == event.user_id:
                filtered.append(item)
                continue
            if not event.source_ip and not event.host_id and not event.user_id:
                filtered.append(item)
        return filtered

    def _evaluate_rule(
        self,
        *,
        rule: ThreatPatternRule,
        context_events: list[DefenseLogEvent],
    ) -> dict[str, Any] | None:
        code = rule.code
        if code == "BRUTE_FORCE_AUTH":
            return self._eval_brute_force(rule, context_events)
        if code == "LATERAL_MOVEMENT_SCAN":
            return self._eval_lateral_movement(rule, context_events)
        if code == "SUSPICIOUS_COMMAND_EXECUTION":
            return self._eval_suspicious_command(rule, context_events)
        if code == "DATA_EXFILTRATION_PATTERN":
            return self._eval_data_exfiltration(rule, context_events)
        if code == "RANSOMWARE_BEHAVIORAL_PATTERN":
            return self._eval_ransomware_behavior(rule, context_events)
        return None

    def _normalize(self, value: str | None) -> str:
        return (value or "").strip().upper()

    def _message(self, event: DefenseLogEvent) -> str:
        return (event.message or "").lower()

    def _keyword_match(self, message: str, keywords: list[str]) -> bool:
        message_l = message.lower()
        return any(k.lower() in message_l for k in keywords)

    def _event_matches(self, event: DefenseLogEvent, event_types: list[str], keywords: list[str]) -> bool:
        event_type = self._normalize(event.event_type)
        if event_type in {e.upper() for e in event_types}:
            return True
        return self._keyword_match(self._message(event), keywords)

    def _event_context_flag(self, event: DefenseLogEvent, candidate_keys: list[str]) -> bool:
        context = event.event_context or {}
        if not isinstance(context, dict):
            return False
        truthy = {"1", "true", "yes", "on", "suspicious", "malicious", "critical", "high"}
        for key in candidate_keys:
            value = context.get(key)
            if isinstance(value, bool) and value:
                return True
            if isinstance(value, (int, float)) and value > 0:
                return True
            if isinstance(value, str) and value.strip().lower() in truthy:
                return True
        return False

    def _build_match_payload(
        self,
        *,
        rule: ThreatPatternRule,
        matching_events: list[DefenseLogEvent],
        unique_targets: int,
        summary: str,
    ) -> dict[str, Any]:
        threshold = max(int(rule.threshold or 1), 1)
        min_targets = max(int(rule.min_unique_targets or 1), 1)
        evidence_count = len(matching_events)

        confidence = min(
            1.0,
            ((evidence_count / threshold) * 0.7) + ((unique_targets / min_targets) * 0.3),
        )
        base_score = min(
            100.0,
            ((evidence_count / threshold) * 70.0) + ((unique_targets / min_targets) * 30.0),
        )
        score = min(100.0, base_score * float(rule.weight or 1.0))

        event_ids = [e.id for e in matching_events if e.id is not None][-20:]
        evidence_items = [
            {
                "event_id": e.id,
                "event_time": e.event_time.isoformat() + "Z" if e.event_time else None,
                "event_type": e.event_type,
                "severity": e.severity,
                "source_ip": e.source_ip,
                "host_id": e.host_id,
                "user_id": e.user_id,
                "message_excerpt": (e.message or "")[:200],
            }
            for e in matching_events[-10:]
        ]

        context_start = min((e.event_time for e in matching_events), default=None)
        context_end = max((e.event_time for e in matching_events), default=None)

        return {
            "summary": summary,
            "confidence": round(confidence, 4),
            "score": round(score, 2),
            "evidence_count": evidence_count,
            "unique_targets": unique_targets,
            "context_window_start": context_start,
            "context_window_end": context_end,
            "event_ids": event_ids,
            "evidence_items": evidence_items,
        }

    def _eval_brute_force(
        self,
        rule: ThreatPatternRule,
        context_events: list[DefenseLogEvent],
    ) -> dict[str, Any] | None:
        params = rule.extra_params or {}
        event_types = list(params.get("event_types", []))
        keywords = list(params.get("keywords", []))

        matching = [e for e in context_events if self._event_matches(e, event_types, keywords)]
        if len(matching) < int(rule.threshold):
            return None
        unique_users = len({e.user_id for e in matching if e.user_id})
        return self._build_match_payload(
            rule=rule,
            matching_events=matching,
            unique_targets=max(1, unique_users),
            summary=f"Detected {len(matching)} auth failures in {rule.window_minutes} minutes.",
        )

    def _eval_lateral_movement(
        self,
        rule: ThreatPatternRule,
        context_events: list[DefenseLogEvent],
    ) -> dict[str, Any] | None:
        params = rule.extra_params or {}
        event_types = list(params.get("event_types", []))
        keywords = list(params.get("keywords", []))

        matching = [e for e in context_events if self._event_matches(e, event_types, keywords)]
        unique_hosts = len({e.host_id for e in matching if e.host_id})
        if len(matching) < int(rule.threshold) or unique_hosts < int(rule.min_unique_targets):
            return None
        return self._build_match_payload(
            rule=rule,
            matching_events=matching,
            unique_targets=unique_hosts,
            summary=f"Detected lateral movement pattern: {len(matching)} denied/scanned attempts across {unique_hosts} hosts.",
        )

    def _eval_suspicious_command(
        self,
        rule: ThreatPatternRule,
        context_events: list[DefenseLogEvent],
    ) -> dict[str, Any] | None:
        params = rule.extra_params or {}
        event_types = list(params.get("event_types", []))
        keywords = list(params.get("keywords", []))

        matching: list[DefenseLogEvent] = []
        for event in context_events:
            keyword_match = self._keyword_match(self._message(event), keywords)
            type_match = self._normalize(event.event_type) in {e.upper() for e in event_types}
            context_match = self._event_context_flag(
                event,
                ["suspicious_command", "dangerous_command", "process_reputation", "ioc_hit"],
            )
            # For command execution we require explicit suspicious evidence:
            # keyword in message OR suspicious context flag tied to command/process event.
            if keyword_match or (type_match and context_match):
                matching.append(event)
        if len(matching) < int(rule.threshold):
            return None
        unique_hosts = len({e.host_id for e in matching if e.host_id}) or 1
        return self._build_match_payload(
            rule=rule,
            matching_events=matching,
            unique_targets=unique_hosts,
            summary=f"Detected suspicious command execution pattern with {len(matching)} events.",
        )

    def _is_external_ip(self, ip_value: str | None) -> bool:
        if not ip_value:
            return False
        try:
            ip_obj = ipaddress.ip_address(ip_value)
            return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_reserved)
        except ValueError:
            return False

    def _extract_bytes_out(self, event: DefenseLogEvent) -> int:
        context = event.event_context or {}
        raw_value = context.get("bytes_out", 0)
        try:
            return int(raw_value)
        except (TypeError, ValueError):
            return 0

    def _extract_destination(self, event: DefenseLogEvent, field_name: str) -> str | None:
        context = event.event_context or {}
        value = context.get(field_name)
        return str(value) if value is not None else None

    def _eval_data_exfiltration(
        self,
        rule: ThreatPatternRule,
        context_events: list[DefenseLogEvent],
    ) -> dict[str, Any] | None:
        params = rule.extra_params or {}
        event_types = {e.upper() for e in list(params.get("event_types", []))}
        destination_field = str(params.get("destination_field", "destination_ip"))
        bytes_threshold = int(params.get("bytes_out_threshold", 50000000))

        matching = [e for e in context_events if self._normalize(e.event_type) in event_types]
        if len(matching) < int(rule.threshold):
            return None

        total_bytes_out = sum(self._extract_bytes_out(e) for e in matching)
        destinations = {
            self._extract_destination(e, destination_field)
            for e in matching
            if self._is_external_ip(self._extract_destination(e, destination_field))
        }
        unique_targets = len({d for d in destinations if d})
        if total_bytes_out < bytes_threshold or unique_targets < int(rule.min_unique_targets):
            return None

        payload = self._build_match_payload(
            rule=rule,
            matching_events=matching,
            unique_targets=unique_targets,
            summary=(
                f"Potential exfiltration detected: bytes_out={total_bytes_out}, "
                f"external_destinations={unique_targets}."
            ),
        )
        payload["extra"] = {"bytes_out_total": total_bytes_out, "external_destinations": unique_targets}
        return payload

    def _eval_ransomware_behavior(
        self,
        rule: ThreatPatternRule,
        context_events: list[DefenseLogEvent],
    ) -> dict[str, Any] | None:
        params = rule.extra_params or {}
        event_types = list(params.get("event_types", []))
        keywords = list(params.get("keywords", []))
        file_field = str(params.get("file_field", "file_path"))

        matching: list[DefenseLogEvent] = []
        for event in context_events:
            keyword_match = self._keyword_match(self._message(event), keywords)
            type_match = self._normalize(event.event_type) in {e.upper() for e in event_types}
            context_match = self._event_context_flag(
                event,
                ["bulk_file_changes", "mass_rename", "encryption_activity", "backup_deletion", "ioc_hit"],
            )
            if keyword_match or (type_match and context_match):
                matching.append(event)
        if len(matching) < int(rule.threshold):
            return None

        unique_files = {
            (e.event_context or {}).get(file_field)
            for e in matching
            if isinstance(e.event_context, dict) and (e.event_context or {}).get(file_field)
        }
        unique_targets = len(unique_files) if unique_files else 1
        if unique_targets < int(rule.min_unique_targets):
            return None

        return self._build_match_payload(
            rule=rule,
            matching_events=matching,
            unique_targets=unique_targets,
            summary=(
                f"Ransomware-like behavior detected: {len(matching)} suspicious events "
                f"over {unique_targets} files/targets."
            ),
        )

    def _upsert_alert(self, event: DefenseLogEvent, rule: ThreatPatternRule, match: dict[str, Any]) -> ThreatAlert:
        window_start = match.get("context_window_start")
        stmt = select(ThreatAlert).where(
            ThreatAlert.rule_code == rule.code,
            ThreatAlert.source_system == event.source_system,
            ThreatAlert.status == "OPEN",
        )
        if event.source_ip:
            stmt = stmt.where(ThreatAlert.source_ip == event.source_ip)
        if event.host_id:
            stmt = stmt.where(ThreatAlert.host_id == event.host_id)
        if window_start:
            stmt = stmt.where(ThreatAlert.updated_at >= window_start)

        existing = self.session.exec(stmt).first()
        evidence_payload = {
            "event_ids": match.get("event_ids", []),
            "evidence_items": match.get("evidence_items", []),
            "extra": match.get("extra", {}),
        }

        now = datetime.datetime.utcnow()
        if existing:
            existing.score = max(float(existing.score or 0.0), float(match["score"]))
            existing.confidence = max(float(existing.confidence or 0.0), float(match["confidence"]))
            existing.evidence_count = int(match["evidence_count"])
            existing.unique_targets = int(match["unique_targets"])
            existing.summary = str(match["summary"])
            existing.context_window_start = match.get("context_window_start")
            existing.context_window_end = match.get("context_window_end")
            existing.evidence = evidence_payload
            existing.updated_at = now
            self.session.add(existing)
            return existing

        alert = ThreatAlert(
            repository_id=event.repository_id,
            rule_code=rule.code,
            source_system=event.source_system,
            source_ip=event.source_ip,
            host_id=event.host_id,
            severity=rule.severity,
            score=float(match["score"]),
            confidence=float(match["confidence"]),
            status="OPEN",
            summary=str(match["summary"]),
            context_window_start=match.get("context_window_start"),
            context_window_end=match.get("context_window_end"),
            evidence_count=int(match["evidence_count"]),
            unique_targets=int(match["unique_targets"]),
            evidence=evidence_payload,
            created_at=now,
            updated_at=now,
        )
        self.session.add(alert)
        return alert

    def _recommend_action(self, alerts: list[ThreatAlert]) -> str:
        if not alerts:
            return "NONE"
        highest_score = max(float(a.score or 0.0) for a in alerts)
        severities = {str(a.severity).upper() for a in alerts}
        if "CRITICAL" in severities or highest_score >= 85.0:
            return "TRIGGER_CONTAINMENT"
        if "HIGH" in severities or highest_score >= 65.0:
            return "ESCALATE_SOC"
        return "MANUAL_REVIEW"

    def list_rules(self) -> list[ThreatPatternRuleRead]:
        rules = list(self.session.exec(select(ThreatPatternRule).order_by(ThreatPatternRule.code)).all())
        return [ThreatPatternRuleRead.model_validate(r) for r in rules]
