import unittest

from app.services.risk_scoring_service import RiskScoringService


class TestRiskScoringService(unittest.TestCase):
    def setUp(self):
        self.service = RiskScoringService()

    def test_low_risk_for_benign_reports_without_dast_signal(self):
        reports = [
            {"security_status": "BENIGN", "risk_score": 20.0},
            {"security_status": "BENIGN", "risk_score": 24.0},
        ]
        dast_result = {
            "status": "SUCCESS",
            "container_exit_code": 0,
            "network_capture": {"status": "NO_CAPTURE_OUTPUT", "metrics": {}},
        }
        result = self.service.compute_unified_risk(reports, dast_result)

        self.assertLess(result["risk_score"], 25.0)
        self.assertEqual(result["risk_level"], "LOW")
        self.assertEqual(result["formula_version"], "v1.0.0")

    def test_critical_risk_for_high_sast_and_failed_dast(self):
        reports = [
            {"security_status": "MALICIOUS", "risk_score": 95.0},
            {"security_status": "MALICIOUS", "risk_score": 92.0},
            {"security_status": "SUSPICIOUS", "risk_score": 80.0},
        ]
        dast_result = {
            "status": "FAILED",
            "container_exit_code": 1,
            "network_capture": {"status": "UNAVAILABLE", "metrics": {}},
        }
        result = self.service.compute_unified_risk(reports, dast_result)

        self.assertGreaterEqual(result["risk_score"], 75.0)
        self.assertEqual(result["risk_level"], "CRITICAL")
        self.assertAlmostEqual(result["weights"]["sast"], 0.60)
        self.assertAlmostEqual(result["weights"]["dast"], 0.40)

    def test_parsed_dast_metrics_raise_dast_component(self):
        reports = [{"security_status": "BENIGN", "risk_score": 30.0}]
        dast_result = {
            "status": "SUCCESS",
            "container_exit_code": 0,
            "network_capture": {
                "status": "PARSED",
                "metrics": {
                    "packets_total": 250,
                    "unique_destinations": 12,
                    "unique_destination_ports": 20,
                    "dns_queries_count": 10,
                    "tcp_syn_attempts": 16,
                },
            },
        }

        result = self.service.compute_unified_risk(reports, dast_result)
        self.assertGreater(result["components"]["dast_score"], 0.0)
        self.assertIn(result["risk_level"], {"LOW", "MEDIUM", "HIGH", "CRITICAL"})


if __name__ == "__main__":
    unittest.main()

