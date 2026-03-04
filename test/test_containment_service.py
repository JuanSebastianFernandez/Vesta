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


class TestContainmentService(unittest.TestCase):
    def setUp(self):
        self.session = _FakeSession()
        self.service = ContainmentService(session=self.session)

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


if __name__ == "__main__":
    unittest.main()
