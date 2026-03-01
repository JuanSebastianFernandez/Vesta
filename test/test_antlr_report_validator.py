import unittest

from app.services.antlr_report_validator import AntlrReportValidator


class TestAntlrReportValidator(unittest.TestCase):
    def setUp(self):
        self.validator = AntlrReportValidator()

    def test_valid_report(self):
        antlr_report = [
            {
                "finding_type": "CODE_EXECUTION",
                "severity": "CRITICAL",
                "line": 12,
                "weight": 0.95,
            }
        ]
        antlr_features = {"antlr_signals": {"findings_count": 1}}

        result = self.validator.validate(
            antlr_report=antlr_report,
            amount_findings=1,
            antlr_features=antlr_features,
        )

        self.assertTrue(result["is_valid"])
        self.assertEqual(result["summary"]["invalid_components"], 0)
        self.assertEqual(len(result["issues"]), 0)

    def test_invalid_component_and_mismatch(self):
        antlr_report = [
            {
                "finding_type": "",
                "severity": "BAD",
                "line": -1,
                "weight": 4.2,
            }
        ]
        antlr_features = {"antlr_signals": {"findings_count": 4}}

        result = self.validator.validate(
            antlr_report=antlr_report,
            amount_findings=2,
            antlr_features=antlr_features,
        )

        self.assertFalse(result["is_valid"])
        self.assertGreaterEqual(len(result["issues"]), 2)
        self.assertEqual(result["summary"]["invalid_components"], 1)
        self.assertFalse(result["components"][0]["valid"])


if __name__ == "__main__":
    unittest.main()

