import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.services.dynamic_analysis_service import DynamicAnalysisService


class TestDynamicAnalysisService(unittest.TestCase):
    def setUp(self):
        self.service = DynamicAnalysisService()

    def test_probe_mode_is_profiled_when_profile_exists(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo_path = Path(tmp_dir)
            profile_path = repo_path / ".vesta" / "dast.profile.json"
            profile_path.parent.mkdir(parents=True, exist_ok=True)
            profile_path.write_text('{"command":["python","app/server.py"]}', encoding="utf-8")
            self.assertEqual(self.service._probe_mode(repo_path), "profiled_probe")

    def test_probe_mode_is_generic_without_profile(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo_path = Path(tmp_dir)
            self.assertEqual(self.service._probe_mode(repo_path), "generic_probe")

    def test_wait_for_container_exit_times_out_cleanly(self):
        class FakeContainer:
            def __init__(self):
                self.attrs = {"State": {"Status": "running", "ExitCode": None}}

            def reload(self):
                return None

        self.service.timeout_seconds = 0
        with patch("app.services.dynamic_analysis_service.time.sleep", return_value=None):
            exit_code, timed_out = self.service._wait_for_container_exit(FakeContainer())

        self.assertEqual(exit_code, -1)
        self.assertTrue(timed_out)


if __name__ == "__main__":
    unittest.main()
