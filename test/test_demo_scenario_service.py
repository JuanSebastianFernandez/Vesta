import unittest
from types import SimpleNamespace

from app.services.demo_scenario_service import DemoScenarioService


class TestDemoScenarioService(unittest.TestCase):
    def test_scenario_event_ids_are_unique_per_run(self):
        service = DemoScenarioService.__new__(DemoScenarioService)

        first = service._scenario_ransomware(SimpleNamespace(repository_id=None), "ransomware-run-a")
        second = service._scenario_ransomware(SimpleNamespace(repository_id=None), "ransomware-run-b")

        first_ids = [item.raw_payload["event_id"] for item in first]
        second_ids = [item.raw_payload["event_id"] for item in second]

        self.assertNotEqual(first_ids, second_ids)
        self.assertTrue(all(value.startswith("ransomware-run-a-") for value in first_ids))
        self.assertTrue(all(value.startswith("ransomware-run-b-") for value in second_ids))

    def test_ransomware_still_attempts_honeypot_when_isolation_fails(self):
        service = DemoScenarioService.__new__(DemoScenarioService)
        service.runtime_service = SimpleNamespace(smartgrid_host_id="smartgrid-app")

        class _ContainmentStub:
            def isolate_node(self, payload):
                _ = payload
                raise ValueError("simulated isolation failure")

            def deploy_honeypot(self, payload):
                _ = payload
                return SimpleNamespace(
                    model_dump=lambda mode="json": {
                        "action_type": "DEPLOY_HONEYPOT",
                        "status": "EXECUTED",
                        "execution_mode": "DEMO_DOCKER",
                        "target_value": "smartgrid-decoy",
                    }
                )

        service.containment_service = _ContainmentStub()

        responses = [SimpleNamespace(triggered_alerts=[SimpleNamespace(id=7, score=100.0)])]
        actions = service._run_follow_up_containment(
            scenario_code="ransomware",
            requested_by="demo.frontend",
            repository_id=None,
            responses=responses,
        )

        self.assertEqual(len(actions), 2)
        self.assertEqual(actions[0]["action_type"], "ISOLATE_NODE")
        self.assertEqual(actions[0]["status"], "FAILED")
        self.assertEqual(actions[1]["action_type"], "DEPLOY_HONEYPOT")
        self.assertEqual(actions[1]["status"], "EXECUTED")


if __name__ == "__main__":
    unittest.main()
