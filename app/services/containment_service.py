from __future__ import annotations

import datetime
import ipaddress
from typing import Any

from sqlmodel import Session, select

from app.models.containment_models import (
    BlockIpRequest,
    ContainmentActionAudit,
    ContainmentActionAuditRead,
    ContainmentActionResponse,
    ContainmentActionStatusUpdate,
    DeployHoneypotRequest,
    IsolateNodeRequest,
    RestoreBackupRequest,
)
from app.services.demo_runtime_service import DemoRuntimeService
from app.utilities.logger import logger


class ContainmentService:
    """
    Containment orchestration service (MVP STUB).
    Persists every requested action for full auditability.
    """

    def __init__(self, session: Session, runtime_service: DemoRuntimeService | None = None):
        self.session = session
        self.runtime_service = runtime_service or DemoRuntimeService(session=session)

    @staticmethod
    def _validate_non_empty(value: str, field_name: str) -> str:
        cleaned = (value or "").strip()
        if not cleaned:
            raise ValueError(f"'{field_name}' cannot be empty.")
        return cleaned

    @staticmethod
    def _validate_ip(ip_value: str) -> str:
        candidate = (ip_value or "").strip()
        try:
            ipaddress.ip_address(candidate)
        except ValueError as exc:
            raise ValueError(f"Invalid IP address '{ip_value}'.") from exc
        return candidate

    @staticmethod
    def _normalize_direction(value: str) -> str:
        normalized = (value or "").strip().upper()
        if normalized not in {"INBOUND", "OUTBOUND", "BOTH"}:
            raise ValueError("Invalid direction. Allowed: INBOUND, OUTBOUND, BOTH.")
        return normalized

    @staticmethod
    def _normalize_status(value: str) -> str:
        normalized = (value or "").strip().upper()
        if normalized not in {"REQUESTED", "SIMULATED_EXECUTED", "EXECUTED", "FAILED", "ROLLED_BACK", "CANCELED"}:
            raise ValueError(
                "Invalid status. Allowed: REQUESTED, SIMULATED_EXECUTED, EXECUTED, FAILED, ROLLED_BACK, CANCELED."
            )
        return normalized

    def _persist_action(
        self,
        *,
        action_type: str,
        target_type: str,
        target_value: str,
        reason: str,
        requested_by: str,
        repository_id: int | None,
        source_alert_id: int | None,
        correlation_id: str | None,
        details: dict[str, Any],
        status: str,
        execution_mode: str = "STUB",
        provider: str = "LOCAL_STUB",
        error_message: str | None = None,
    ) -> ContainmentActionAudit:
        now = datetime.datetime.utcnow()
        record = ContainmentActionAudit(
            repository_id=repository_id,
            source_alert_id=source_alert_id,
            correlation_id=correlation_id,
            action_type=action_type,
            target_type=target_type,
            target_value=target_value,
            reason=reason,
            requested_by=requested_by,
            status=status,
            execution_mode=execution_mode,
            provider=provider,
            details=details,
            error_message=error_message,
            requested_at=now,
            executed_at=now if status in {"SIMULATED_EXECUTED", "EXECUTED"} else None,
            updated_at=now,
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def isolate_node(self, payload: IsolateNodeRequest) -> ContainmentActionResponse:
        requested_by = self._validate_non_empty(payload.requested_by, "requested_by")
        reason = self._validate_non_empty(payload.reason, "reason")
        host_id = self._validate_non_empty(payload.host_id, "host_id")

        details = {
            "dry_run": payload.dry_run,
            "network_segment": payload.network_segment,
            "quarantine_policy": payload.quarantine_policy,
            "metadata": payload.request_metadata or {},
            "execution_plan": [
                f"Tag endpoint '{host_id}' as quarantine candidate.",
                "Revoke east-west lateral movement ACL.",
                "Apply deny-all egress with SOC exception list.",
            ],
        }

        if not payload.dry_run and self.runtime_service.enabled:
            try:
                runtime_details = self.runtime_service.isolate_host(host_id)
                details["runtime"] = runtime_details
                record = self._persist_action(
                    action_type="ISOLATE_NODE",
                    target_type="HOST",
                    target_value=host_id,
                    reason=reason,
                    requested_by=requested_by,
                    repository_id=payload.repository_id,
                    source_alert_id=payload.source_alert_id,
                    correlation_id=payload.correlation_id,
                    details=details,
                    status="EXECUTED",
                    execution_mode="DEMO_DOCKER",
                    provider=self.runtime_service.provider,
                )
                logger.warning(
                    "[Containment] Demo node isolation host_id=%s requested_by=%s audit_id=%s",
                    host_id,
                    requested_by,
                    record.id,
                )
                return ContainmentActionResponse(
                    audit=ContainmentActionAuditRead.model_validate(record),
                    message="Node isolated in demo runtime and audited.",
                    next_steps=[
                        "Validate the node is attached only to the quarantine network.",
                        "Review defense alerts linked to this isolation.",
                        "Use the containment panel to monitor runtime state changes.",
                    ],
                )
            except Exception as exc:  # noqa: BLE001
                details["runtime_error"] = str(exc)
                record = self._persist_action(
                    action_type="ISOLATE_NODE",
                    target_type="HOST",
                    target_value=host_id,
                    reason=reason,
                    requested_by=requested_by,
                    repository_id=payload.repository_id,
                    source_alert_id=payload.source_alert_id,
                    correlation_id=payload.correlation_id,
                    details=details,
                    status="FAILED",
                    execution_mode="DEMO_DOCKER",
                    provider=self.runtime_service.provider,
                    error_message=str(exc),
                )
                raise ValueError(
                    f"Demo runtime isolation failed for host '{host_id}'. audit_id={record.id}. reason={exc}"
                ) from exc

        record = self._persist_action(
            action_type="ISOLATE_NODE",
            target_type="HOST",
            target_value=host_id,
            reason=reason,
            requested_by=requested_by,
            repository_id=payload.repository_id,
            source_alert_id=payload.source_alert_id,
            correlation_id=payload.correlation_id,
            details=details,
            status="SIMULATED_EXECUTED",
        )

        logger.warning(
            f"[Containment] Simulated node isolation host_id={host_id} requested_by={requested_by} audit_id={record.id}"
        )
        return ContainmentActionResponse(
            audit=ContainmentActionAuditRead.model_validate(record),
            message="Node isolation simulated and audited.",
            next_steps=[
                "Confirm host ownership with ITSM inventory.",
                "Collect volatile memory before hard shutdown.",
                "Open incident bridge with SOC + IT Ops.",
            ],
        )

    def block_ip(self, payload: BlockIpRequest) -> ContainmentActionResponse:
        requested_by = self._validate_non_empty(payload.requested_by, "requested_by")
        reason = self._validate_non_empty(payload.reason, "reason")
        ip_value = self._validate_ip(payload.ip_address)
        direction = self._normalize_direction(payload.direction)
        duration_minutes = max(int(payload.duration_minutes), 1)

        details = {
            "dry_run": payload.dry_run,
            "direction": direction,
            "duration_minutes": duration_minutes,
            "rule_scope": payload.rule_scope,
            "metadata": payload.request_metadata or {},
            "execution_plan": [
                f"Create temporary block rule for {ip_value}.",
                f"Apply direction={direction} on scope={payload.rule_scope}.",
                f"Schedule automatic review after {duration_minutes} minutes.",
            ],
        }

        record = self._persist_action(
            action_type="BLOCK_IP_RULE",
            target_type="IP",
            target_value=ip_value,
            reason=reason,
            requested_by=requested_by,
            repository_id=payload.repository_id,
            source_alert_id=payload.source_alert_id,
            correlation_id=payload.correlation_id,
            details=details,
            status="SIMULATED_EXECUTED",
        )

        logger.warning(
            f"[Containment] Simulated IP block ip={ip_value} direction={direction} requested_by={requested_by} audit_id={record.id}"
        )
        return ContainmentActionResponse(
            audit=ContainmentActionAuditRead.model_validate(record),
            message="IP block action simulated and audited.",
            next_steps=[
                "Verify no business-critical dependency on blocked IP.",
                "Correlate with threat intel feeds for confidence.",
                "Promote temporary rule to permanent if compromise is confirmed.",
            ],
        )

    def restore_backup(self, payload: RestoreBackupRequest) -> ContainmentActionResponse:
        requested_by = self._validate_non_empty(payload.requested_by, "requested_by")
        reason = self._validate_non_empty(payload.reason, "reason")
        asset_id = self._validate_non_empty(payload.asset_id, "asset_id")

        details = {
            "dry_run": payload.dry_run,
            "backup_snapshot_id": payload.backup_snapshot_id,
            "restore_strategy": payload.restore_strategy,
            "validate_hash_before_restore": payload.validate_hash_before_restore,
            "metadata": payload.request_metadata or {},
            "execution_plan": [
                f"Locate immutable backup for asset '{asset_id}'.",
                "Validate backup integrity/hash before restore.",
                "Restore to isolated cleanroom before production cutover.",
            ],
        }

        record = self._persist_action(
            action_type="RESTORE_BACKUP",
            target_type="ASSET",
            target_value=asset_id,
            reason=reason,
            requested_by=requested_by,
            repository_id=payload.repository_id,
            source_alert_id=payload.source_alert_id,
            correlation_id=payload.correlation_id,
            details=details,
            status="SIMULATED_EXECUTED",
        )

        logger.warning(
            f"[Containment] Simulated backup restore asset_id={asset_id} requested_by={requested_by} audit_id={record.id}"
        )
        return ContainmentActionResponse(
            audit=ContainmentActionAuditRead.model_validate(record),
            message="Backup restoration workflow simulated and audited.",
            next_steps=[
                "Perform malware scan on restored image before reconnect.",
                "Rotate credentials/secrets used by compromised asset.",
                "Run post-incident verification checklist.",
            ],
        )

    def deploy_honeypot(self, payload: DeployHoneypotRequest) -> ContainmentActionResponse:
        requested_by = self._validate_non_empty(payload.requested_by, "requested_by")
        reason = self._validate_non_empty(payload.reason, "reason")
        decoy_target = self._validate_non_empty(payload.decoy_target, "decoy_target")
        ttl_minutes = max(int(payload.ttl_minutes), 15)
        profile = self._validate_non_empty(payload.honeypot_profile, "honeypot_profile").upper()

        details = {
            "dry_run": payload.dry_run,
            "honeypot_profile": profile,
            "ttl_minutes": ttl_minutes,
            "network_zone": payload.network_zone,
            "metadata": payload.request_metadata or {},
            "execution_plan": [
                f"Deploy honeypot profile '{profile}' for decoy '{decoy_target}'.",
                "Apply strict egress-deny and full packet capture mode.",
                f"Schedule teardown/rebuild cycle after {ttl_minutes} minutes.",
            ],
            "honey_pot_behavior": {
                "telemetry_capture": ["network", "auth_attempts", "command_sequences"],
                "response_mode": "passive_deception",
                "lateral_movement_traps": True,
            },
        }

        if not payload.dry_run and self.runtime_service.enabled:
            try:
                runtime_details = self.runtime_service.deploy_honeypot(
                    honeypot_profile=profile,
                    ttl_minutes=ttl_minutes,
                    network_zone=payload.network_zone,
                )
                details["runtime"] = runtime_details
                details["ttl_minutes"] = runtime_details.get("ttl_minutes", ttl_minutes)
                details["expires_at"] = runtime_details.get("expires_at")
                record = self._persist_action(
                    action_type="DEPLOY_HONEYPOT",
                    target_type="DECOY",
                    target_value=decoy_target,
                    reason=reason,
                    requested_by=requested_by,
                    repository_id=payload.repository_id,
                    source_alert_id=payload.source_alert_id,
                    correlation_id=payload.correlation_id,
                    details=details,
                    status="EXECUTED",
                    execution_mode="DEMO_DOCKER",
                    provider=self.runtime_service.provider,
                )
                logger.warning(
                    "[Containment] Demo honeypot deployment target=%s profile=%s audit_id=%s",
                    decoy_target,
                    profile,
                    record.id,
                )
                return ContainmentActionResponse(
                    audit=ContainmentActionAuditRead.model_validate(record),
                    message="Honeypot deployed in demo runtime and audited.",
                    next_steps=[
                        "Use the containment panel to verify the honeypot is active.",
                        "Link new attacker interactions to defense evidence if needed.",
                        "Tear down or redeploy the honeypot after TTL expiration.",
                    ],
                )
            except Exception as exc:  # noqa: BLE001
                details["runtime_error"] = str(exc)
                record = self._persist_action(
                    action_type="DEPLOY_HONEYPOT",
                    target_type="DECOY",
                    target_value=decoy_target,
                    reason=reason,
                    requested_by=requested_by,
                    repository_id=payload.repository_id,
                    source_alert_id=payload.source_alert_id,
                    correlation_id=payload.correlation_id,
                    details=details,
                    status="FAILED",
                    execution_mode="DEMO_DOCKER",
                    provider=self.runtime_service.provider,
                    error_message=str(exc),
                )
                raise ValueError(
                    f"Demo runtime honeypot deployment failed for '{decoy_target}'. audit_id={record.id}. reason={exc}"
                ) from exc

        record = self._persist_action(
            action_type="DEPLOY_HONEYPOT",
            target_type="DECOY",
            target_value=decoy_target,
            reason=reason,
            requested_by=requested_by,
            repository_id=payload.repository_id,
            source_alert_id=payload.source_alert_id,
            correlation_id=payload.correlation_id,
            details=details,
            status="SIMULATED_EXECUTED",
        )

        logger.warning(
            f"[Containment] Simulated honeypot deployment target={decoy_target} profile={profile} audit_id={record.id}"
        )
        return ContainmentActionResponse(
            audit=ContainmentActionAuditRead.model_validate(record),
            message="Honeypot deployment simulated and audited.",
            next_steps=[
                "Connect honeypot telemetry to SIEM and case management.",
                "Validate no routing path from honeypot to production crown jewels.",
                "Tune deception signatures based on attacker interaction.",
            ],
        )

    def list_actions(
        self,
        *,
        page: int,
        page_size: int,
        action_type: str | None = None,
        status: str | None = None,
        requested_by: str | None = None,
        repository_id: int | None = None,
        source_alert_id: int | None = None,
    ) -> dict[str, Any]:
        stmt = select(ContainmentActionAudit)
        if action_type:
            stmt = stmt.where(ContainmentActionAudit.action_type == action_type.upper())
        if status:
            stmt = stmt.where(ContainmentActionAudit.status == status.upper())
        if requested_by:
            stmt = stmt.where(ContainmentActionAudit.requested_by == requested_by)
        if repository_id is not None:
            stmt = stmt.where(ContainmentActionAudit.repository_id == repository_id)
        if source_alert_id is not None:
            stmt = stmt.where(ContainmentActionAudit.source_alert_id == source_alert_id)

        items_all = list(self.session.exec(stmt.order_by(ContainmentActionAudit.requested_at.desc())).all())
        total = len(items_all)
        start = (page - 1) * page_size
        items = items_all[start:start + page_size]

        return {
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total_actions": total,
                "total_pages": (total + page_size - 1) // page_size if total > 0 else 0,
            },
            "items": [ContainmentActionAuditRead.model_validate(x).model_dump(mode="json") for x in items],
        }

    def get_action(self, action_id: int) -> ContainmentActionAuditRead | None:
        action = self.session.get(ContainmentActionAudit, action_id)
        if not action:
            return None
        return ContainmentActionAuditRead.model_validate(action)

    def update_action_status(self, action_id: int, payload: ContainmentActionStatusUpdate) -> ContainmentActionAuditRead | None:
        action = self.session.get(ContainmentActionAudit, action_id)
        if not action:
            return None
        action.status = self._normalize_status(payload.status)
        action.error_message = payload.error_message
        action.updated_at = datetime.datetime.utcnow()
        if action.status in {"SIMULATED_EXECUTED", "ROLLED_BACK"}:
            action.executed_at = action.executed_at or datetime.datetime.utcnow()
        self.session.add(action)
        self.session.commit()
        self.session.refresh(action)
        return ContainmentActionAuditRead.model_validate(action)
