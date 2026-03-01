import datetime
import unittest

from app.models.defense_models import DefenseLogEvent, ThreatPatternRule
from app.services.network_analyzer_service import NetworkAnalyzerService


class _DummySession:
    pass


class TestNetworkAnalyzerServiceRules(unittest.TestCase):
    def setUp(self):
        self.service = NetworkAnalyzerService(session=_DummySession())
        self.now = datetime.datetime.utcnow()

    def _event(
        self,
        *,
        event_type: str,
        message: str,
        source_ip: str = "10.0.0.8",
        host_id: str = "host-1",
        user_id: str = "user-1",
        context: dict | None = None,
        offset_seconds: int = 0,
    ) -> DefenseLogEvent:
        return DefenseLogEvent(
            source_system="EDR",
            source_ip=source_ip,
            host_id=host_id,
            user_id=user_id,
            event_type=event_type,
            message=message,
            event_time=self.now + datetime.timedelta(seconds=offset_seconds),
            event_context=context or {},
            raw_payload={},
        )

    def test_brute_force_rule_detects_repeated_failures(self):
        rule = ThreatPatternRule(
            code="BRUTE_FORCE_AUTH",
            name="Auth Brute Force",
            description="Test brute force",
            severity="HIGH",
            weight=1.0,
            window_minutes=10,
            threshold=6,
            min_unique_targets=1,
            extra_params={
                "event_types": ["AUTH_FAILURE"],
                "keywords": ["failed login"],
            },
        )
        events = [
            self._event(event_type="AUTH_FAILURE", message="failed login for user x", offset_seconds=i)
            for i in range(6)
        ]

        result = self.service._eval_brute_force(rule, events)
        self.assertIsNotNone(result)
        self.assertEqual(result["evidence_count"], 6)
        self.assertGreaterEqual(result["score"], 70.0)

    def test_data_exfiltration_rule_detects_high_outbound_volume(self):
        rule = ThreatPatternRule(
            code="DATA_EXFILTRATION_PATTERN",
            name="Potential Data Exfiltration",
            description="Test exfiltration",
            severity="CRITICAL",
            weight=1.3,
            window_minutes=30,
            threshold=3,
            min_unique_targets=2,
            extra_params={
                "event_types": ["DATA_TRANSFER"],
                "bytes_out_threshold": 50_000_000,
                "destination_field": "destination_ip",
            },
        )
        events = [
            self._event(
                event_type="DATA_TRANSFER",
                message="outbound transfer",
                context={"bytes_out": 20_000_000, "destination_ip": "8.8.8.8"},
                offset_seconds=1,
            ),
            self._event(
                event_type="DATA_TRANSFER",
                message="outbound transfer",
                context={"bytes_out": 20_000_000, "destination_ip": "1.1.1.1"},
                offset_seconds=2,
            ),
            self._event(
                event_type="DATA_TRANSFER",
                message="outbound transfer",
                context={"bytes_out": 20_000_000, "destination_ip": "8.8.8.8"},
                offset_seconds=3,
            ),
        ]

        result = self.service._eval_data_exfiltration(rule, events)
        self.assertIsNotNone(result)
        self.assertEqual(result["extra"]["bytes_out_total"], 60_000_000)
        self.assertGreaterEqual(result["extra"]["external_destinations"], 2)

    def test_ransomware_rule_requires_behavioral_signal(self):
        rule = ThreatPatternRule(
            code="RANSOMWARE_BEHAVIORAL_PATTERN",
            name="Ransomware Behavioral Pattern",
            description="Test ransomware",
            severity="CRITICAL",
            weight=1.4,
            window_minutes=20,
            threshold=4,
            min_unique_targets=2,
            extra_params={
                "event_types": ["FILE_OPERATION", "PROCESS_CREATE"],
                "keywords": ["encrypt", ".encrypted", "delete backups"],
                "file_field": "file_path",
            },
        )

        benign_events = [
            self._event(
                event_type="FILE_OPERATION",
                message="normal write operation",
                context={"file_path": f"/tmp/file_{i}.txt"},
                offset_seconds=i,
            )
            for i in range(4)
        ]
        self.assertIsNone(self.service._eval_ransomware_behavior(rule, benign_events))

        suspicious_events = [
            self._event(
                event_type="FILE_OPERATION",
                message="encrypt file started",
                context={"file_path": "/data/a.txt", "encryption_activity": True},
                offset_seconds=1,
            ),
            self._event(
                event_type="FILE_OPERATION",
                message="encrypt file started",
                context={"file_path": "/data/b.txt", "encryption_activity": True},
                offset_seconds=2,
            ),
            self._event(
                event_type="PROCESS_CREATE",
                message="delete backups now",
                context={"file_path": "/data/c.txt", "backup_deletion": True},
                offset_seconds=3,
            ),
            self._event(
                event_type="FILE_OPERATION",
                message="file extension changed to .encrypted",
                context={"file_path": "/data/d.txt", "mass_rename": True},
                offset_seconds=4,
            ),
        ]
        result = self.service._eval_ransomware_behavior(rule, suspicious_events)
        self.assertIsNotNone(result)
        self.assertGreaterEqual(result["unique_targets"], 2)
        self.assertGreaterEqual(result["evidence_count"], 4)


if __name__ == "__main__":
    unittest.main()
