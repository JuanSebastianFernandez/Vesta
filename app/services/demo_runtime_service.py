from __future__ import annotations

import datetime
from typing import Any

from sqlmodel import Session, select

from app.core.config import settings
from app.models.containment_models import ContainmentActionAudit
from app.models.demo_models import DemoRuntimeAsset, DemoRuntimeAssetsResponse
from app.utilities.logger import logger


class DemoRuntimeService:
    """
    Docker-backed laboratory runtime for demo-only containment actions.
    """

    def __init__(self, session: Session | None = None) -> None:
        self.session = session
        self.enabled = settings.DEMO_RUNTIME_ENABLED
        self.provider = settings.DEMO_RUNTIME_PROVIDER
        self.smartgrid_host_id = settings.DEMO_RUNTIME_SMARTGRID_HOST_ID
        self.container_map = {
            settings.DEMO_RUNTIME_SMARTGRID_HOST_ID: settings.DEMO_RUNTIME_SMARTGRID_CONTAINER,
            "smartgrid-db": settings.DEMO_RUNTIME_DB_CONTAINER,
            "attacker-sim": settings.DEMO_RUNTIME_ATTACKER_CONTAINER,
            "honeypot": settings.DEMO_RUNTIME_HONEYPOT_CONTAINER,
            "collector": settings.DEMO_RUNTIME_COLLECTOR_CONTAINER,
        }
        self.prod_network = settings.DEMO_RUNTIME_PROD_NETWORK
        self.quarantine_network = settings.DEMO_RUNTIME_QUARANTINE_NETWORK
        self.deception_network = settings.DEMO_RUNTIME_DECEPTION_NETWORK
        self.honeypot_port = settings.DEMO_RUNTIME_HONEYPOT_PORT
        self._docker_client: Any = None

    def _get_client(self):
        if self._docker_client is not None:
            return self._docker_client
        try:
            import docker  # type: ignore
        except Exception as exc:  # pragma: no cover - environment-dependent
            raise RuntimeError(f"Docker SDK not available: {exc}") from exc

        self._docker_client = docker.from_env()
        return self._docker_client

    def _get_container(self, container_name: str):
        client = self._get_client()
        return client.containers.get(container_name)

    def _get_network(self, network_name: str):
        client = self._get_client()
        return client.networks.get(network_name)

    def _resolve_network_name(self, network_name: str | None, default_name: str) -> str:
        candidate = (network_name or "").strip()
        if not candidate:
            return default_name

        aliases = {
            "demo_prod": self.prod_network,
            "demo_quarantine": self.quarantine_network,
            "demo_deception": self.deception_network,
            self.prod_network: self.prod_network,
            self.quarantine_network: self.quarantine_network,
            self.deception_network: self.deception_network,
        }
        return aliases.get(candidate, candidate)

    def _ensure_network(self, network_name: str):
        client = self._get_client()
        existing = client.networks.list(names=[network_name])
        if existing:
            return existing[0]
        logger.warning("[DemoRuntime] Creating missing Docker network '%s'.", network_name)
        return client.networks.create(network_name, driver="bridge")

    def _list_networks(self, container: Any) -> list[str]:
        network_settings = ((container.attrs or {}).get("NetworkSettings") or {}).get("Networks") or {}
        return sorted(network_settings.keys())

    def _list_ports(self, container: Any) -> list[str]:
        port_bindings = ((container.attrs or {}).get("NetworkSettings") or {}).get("Ports") or {}
        ports: list[str] = []
        for container_port, host_bindings in port_bindings.items():
            if not host_bindings:
                ports.append(container_port)
                continue
            for item in host_bindings:
                host_ip = item.get("HostIp", "")
                host_port = item.get("HostPort", "")
                ports.append(f"{host_ip}:{host_port}->{container_port}")
        return ports

    def _build_asset(self, host_id: str, container_name: str) -> DemoRuntimeAsset:
        container = self._get_container(container_name)
        container.reload()
        networks = self._list_networks(container)
        return DemoRuntimeAsset(
            host_id=host_id,
            container_name=container.name,
            status=str(container.status).upper(),
            image=str((container.attrs or {}).get("Config", {}).get("Image", "")),
            networks=networks,
            quarantine=self.quarantine_network in networks,
            honeypot=container.name == settings.DEMO_RUNTIME_HONEYPOT_CONTAINER,
            ports=self._list_ports(container),
            attributes={
                "container_id": getattr(container, "short_id", ""),
                "prod_network": self.prod_network in networks,
                "deception_network": self.deception_network in networks,
            },
        )

    def _latest_honeypot_action(self) -> ContainmentActionAudit | None:
        if self.session is None:
            return None
        stmt = (
            select(ContainmentActionAudit)
            .where(ContainmentActionAudit.action_type == "DEPLOY_HONEYPOT")
            .order_by(ContainmentActionAudit.requested_at.desc())
        )
        return self.session.exec(stmt).first()

    def list_assets(self) -> DemoRuntimeAssetsResponse:
        if not self.enabled:
            return DemoRuntimeAssetsResponse(enabled=False, provider=self.provider, assets=[])

        assets: list[DemoRuntimeAsset] = []
        errors: list[str] = []
        for host_id, container_name in self.container_map.items():
            try:
                assets.append(self._build_asset(host_id=host_id, container_name=container_name))
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{host_id}: {exc}")

        honeypot_action = self._latest_honeypot_action()
        ttl_minutes: int | None = None
        expires_at: datetime.datetime | None = None
        if honeypot_action:
            ttl_raw = (honeypot_action.details or {}).get("ttl_minutes")
            expires_raw = (honeypot_action.details or {}).get("expires_at")
            try:
                ttl_minutes = int(ttl_raw) if ttl_raw is not None else None
            except (TypeError, ValueError):
                ttl_minutes = None
            if isinstance(expires_raw, str):
                try:
                    expires_at = datetime.datetime.fromisoformat(expires_raw.replace("Z", "+00:00")).replace(
                        tzinfo=None
                    )
                except ValueError:
                    expires_at = None

        last_actions: list[dict[str, Any]] = []
        if self.session is not None:
            stmt = (
                select(ContainmentActionAudit)
                .order_by(ContainmentActionAudit.requested_at.desc())
                .limit(10)
            )
            for action in self.session.exec(stmt).all():
                last_actions.append(
                    {
                        "id": action.id,
                        "action_type": action.action_type,
                        "target_value": action.target_value,
                        "status": action.status,
                        "execution_mode": action.execution_mode,
                        "requested_at": action.requested_at.isoformat() + "Z" if action.requested_at else None,
                    }
                )

        honeypot_asset_running = any(
            asset.honeypot and asset.status == "RUNNING"
            for asset in assets
        )
        honeypot_active = False
        if honeypot_action and honeypot_asset_running:
            honeypot_active = honeypot_action.status in {"EXECUTED", "SIMULATED_EXECUTED"}
            if expires_at is not None and expires_at < datetime.datetime.utcnow():
                honeypot_active = False

        response = DemoRuntimeAssetsResponse(
            enabled=True,
            provider=self.provider,
            assets=assets,
            honeypot_active=honeypot_active,
            honeypot_ttl_minutes=ttl_minutes,
            honeypot_expires_at=expires_at,
            last_actions=last_actions,
        )
        if errors:
            response.last_actions.insert(0, {"status": "WARN", "message": "; ".join(errors)})
        return response

    def isolate_host(self, host_id: str) -> dict[str, Any]:
        if not self.enabled:
            raise RuntimeError("Demo runtime is disabled.")
        container_name = self.container_map.get(host_id)
        if not container_name:
            raise ValueError(f"Unknown demo host_id '{host_id}'.")

        container = self._get_container(container_name)
        container.reload()
        before_networks = self._list_networks(container)

        prod_network = self._ensure_network(self.prod_network)
        quarantine_network = self._ensure_network(self.quarantine_network)

        if self.prod_network in before_networks:
            try:
                prod_network.disconnect(container, force=True)
            except Exception as exc:  # noqa: BLE001
                logger.warning(f"[DemoRuntime] Failed disconnecting '{host_id}' from prod network: {exc}")

        if self.quarantine_network not in before_networks:
            quarantine_network.connect(container)

        container.reload()
        after_networks = self._list_networks(container)
        return {
            "host_id": host_id,
            "container_name": container_name,
            "before_networks": before_networks,
            "after_networks": after_networks,
            "quarantine": self.quarantine_network in after_networks,
            "executed_at": datetime.datetime.utcnow().isoformat() + "Z",
        }

    def deploy_honeypot(self, *, honeypot_profile: str, ttl_minutes: int, network_zone: str | None) -> dict[str, Any]:
        if not self.enabled:
            raise RuntimeError("Demo runtime is disabled.")

        container = self._get_container(settings.DEMO_RUNTIME_HONEYPOT_CONTAINER)
        container.reload()
        if container.status != "running":
            container.start()

        target_network_name = self._resolve_network_name(network_zone, self.deception_network)
        deception_network = self._ensure_network(target_network_name)
        current_networks = self._list_networks(container)
        if target_network_name not in current_networks:
            try:
                deception_network.connect(container)
            except Exception as exc:  # noqa: BLE001
                if "already exists in network" not in str(exc).lower():
                    raise

        container.reload()
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=max(ttl_minutes, 1))
        networks_after = self._list_networks(container)
        return {
            "container_name": container.name,
            "honeypot_profile": honeypot_profile,
            "network_zone": target_network_name,
            "before_networks": current_networks,
            "after_networks": networks_after,
            "ttl_minutes": max(ttl_minutes, 1),
            "expires_at": expires_at.isoformat() + "Z",
            "ports": self._list_ports(container) or [f"0.0.0.0:{self.honeypot_port}->2222/tcp"],
            "status": str(container.status).upper(),
        }
