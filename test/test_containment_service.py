import unittest

from app.models.containment_models import (
    BlockIpRequest,
    ContainmentActionAudit,
    ContainmentActionStatusUpdate,
    DeployHoneypotRequest,
    IsolateNodeRequest,
)
from app.services.containment_service import ContainmentService


class _FakeExecResult:
    def __init__(self, items):
        self._items = items

    def all(self):
        return list(self._items)

    def first(self):
        items = list(self._items)
        return items[0] if items else None


class _FakeSession:
    def __init__(self):
        self.items = {}
        self.next_id = 1

    def add(self, obj):
        if getattr(obj, "id", None) is None:
            obj.id = self.next_id
            self.next_id += 1
        self.items[obj.id] = obj

    def commit(self):
        return None

    def refresh(self, obj):
        self.items[obj.id] = obj

    def get(self, model, obj_id):
        _ = model
        return self.items.get(obj_id)

    def exec(self, stmt):
        _ = stmt
        return _FakeExecResult(self.items.values())


class _FakeRuntimeService:
    enabled = True
    provider = "DEMO_DOCKER"

    def __init__(self):
        self.isolated = []
        self.honeypots = []

    def isolate_host(self, host_id):
        self.isolated.append(host_id)
        return {
            "host_id": host_id,
            "before_networks": ["vesta_demo_prod"],
            "after_networks": ["vesta_demo_quarantine"],
            "quarantine": True,
        }

    def deploy_honeypot(self, *, honeypot_profile, ttl_minutes, network_zone):
        self.honeypots.append((honeypot_profile, ttl_minutes, network_zone))
        return {
            "container_name": "vesta-demo-honeypot",
            "honeypot_profile": honeypot_profile,
            "ttl_minutes": ttl_minutes,
            "network_zone": network_zone,
            "expires_at": "2030-01-01T00:00:00Z",
            "status": "RUNNING",
        }


class TestContainmentService(unittest.TestCase):
    def setUp(self):
        self.session = _FakeSession()
        self.runtime_service = _FakeRuntimeService()
        self.service = ContainmentService(session=self.session, runtime_service=self.runtime_service)

    def test_isolate_node_creates_audited_action(self):
        payload = IsolateNodeRequest(
            repository_id=7,
            source_alert_id=1,
            correlation_id="corr-1",
            reason="Host indicators suggest active compromise",
            requested_by="soc.analyst",
            dry_run=True,
            host_id="host-a",
            network_segment="seg-a",
            quarantine_policy="default-quarantine",
        )
        result = self.service.isolate_node(payload)
        self.assertEqual(result.audit.action_type, "ISOLATE_NODE")
        self.assertEqual(result.audit.target_type, "HOST")
        self.assertEqual(result.audit.target_value, "host-a")
        self.assertEqual(result.audit.status, "SIMULATED_EXECUTED")

    def test_block_ip_rejects_invalid_ip(self):
        payload = BlockIpRequest(
            reason="Known C2 callback",
            requested_by="soc.analyst",
            ip_address="999.1.1.1",
        )
        with self.assertRaises(ValueError):
            self.service.block_ip(payload)

    def test_deploy_honeypot_contains_behavior_metadata(self):
        payload = DeployHoneypotRequest(
            reason="Collect attacker TTPs in decoy zone",
            requested_by="ir.lead",
            decoy_target="decoy-vlan-20",
            honeypot_profile="cowrie_ssh",
            ttl_minutes=120,
        )
        result = self.service.deploy_honeypot(payload)
        self.assertEqual(result.audit.action_type, "DEPLOY_HONEYPOT")
        self.assertIn("honey_pot_behavior", result.audit.details)

    def test_update_action_status_validates_enum(self):
        record = ContainmentActionAudit(
            action_type="ISOLATE_NODE",
            target_type="HOST",
            target_value="host-a",
            reason="test",
            requested_by="soc",
            status="REQUESTED",
        )
        self.session.add(record)
        with self.assertRaises(ValueError):
            self.service.update_action_status(
                record.id,
                ContainmentActionStatusUpdate(status="NOT_ALLOWED"),
            )

    def test_isolate_node_executes_demo_runtime_when_not_dry_run(self):
        payload = IsolateNodeRequest(
            reason="Contain runtime host in demo lab",
            requested_by="demo.frontend",
            dry_run=False,
            host_id="smartgrid-app",
        )
        result = self.service.isolate_node(payload)
        self.assertEqual(result.audit.execution_mode, "DEMO_DOCKER")
        self.assertEqual(result.audit.status, "EXECUTED")
        self.assertEqual(self.runtime_service.isolated, ["smartgrid-app"])

    def test_deploy_honeypot_executes_demo_runtime_when_not_dry_run(self):
        payload = DeployHoneypotRequest(
            reason="Launch deception asset",
            requested_by="demo.frontend",
            dry_run=False,
            decoy_target="smartgrid-decoy",
            honeypot_profile="cowrie_ssh",
            ttl_minutes=120,
            network_zone="demo_deception",
        )
        result = self.service.deploy_honeypot(payload)
        self.assertEqual(result.audit.execution_mode, "DEMO_DOCKER")
        self.assertEqual(result.audit.status, "EXECUTED")
        self.assertEqual(result.audit.details["ttl_minutes"], 120)
        self.assertEqual(len(self.runtime_service.honeypots), 1)


if __name__ == "__main__":
    unittest.main()
