import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import git

from app.services.repository_manager import RepositoryManager


class TestRepositoryManager(unittest.TestCase):
    def setUp(self):
        self.manager = RepositoryManager()

    def test_normalize_repo_source_treats_github_urls_equally(self):
        source_a = self.manager._normalize_repo_source("https://github.com/JuanSebastianFernandez/smart-grid-repo")
        source_b = self.manager._normalize_repo_source("https://github.com/JuanSebastianFernandez/smart-grid-repo.git/")
        self.assertEqual(source_a, source_b)

    def test_prepare_repository_target_keeps_matching_origin(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo_path = Path(tmp_dir) / "smart-grid-repo"
            repo_path.mkdir()

            with patch.object(self.manager, "_get_repo_path", return_value=repo_path), \
                 patch.object(self.manager, "_is_valid_git_repository", return_value=True), \
                 patch.object(self.manager, "_repo_origin_matches", return_value=True), \
                 patch.object(self.manager, "cleanup_repository") as cleanup_mock:
                result = self.manager._prepare_repository_target(
                    repo_url="https://github.com/JuanSebastianFernandez/smart-grid-repo",
                    repo_name="smart-grid-repo",
                )

            self.assertEqual(result, repo_path)
            cleanup_mock.assert_not_called()

    def test_prepare_repository_target_recreates_invalid_repository(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo_path = Path(tmp_dir) / "smart-grid-repo"
            repo_path.mkdir()

            with patch.object(self.manager, "_get_repo_path", return_value=repo_path), \
                 patch.object(self.manager, "_is_valid_git_repository", return_value=False), \
                 patch.object(self.manager, "cleanup_repository") as cleanup_mock:
                result = self.manager._prepare_repository_target(
                    repo_url="https://github.com/JuanSebastianFernandez/smart-grid-repo",
                    repo_name="smart-grid-repo",
                )

            self.assertEqual(result, repo_path)
            cleanup_mock.assert_called_once_with("smart-grid-repo")

    def test_prepare_repository_target_recreates_repository_when_origin_changes(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo_path = Path(tmp_dir) / "smart-grid-repo"
            repo_path.mkdir()

            with patch.object(self.manager, "_get_repo_path", return_value=repo_path), \
                 patch.object(self.manager, "_is_valid_git_repository", return_value=True), \
                 patch.object(self.manager, "_repo_origin_matches", return_value=False), \
                 patch.object(self.manager, "cleanup_repository") as cleanup_mock:
                result = self.manager._prepare_repository_target(
                    repo_url="https://github.com/JuanSebastianFernandez/smart-grid-repo",
                    repo_name="smart-grid-repo",
                )

            self.assertEqual(result, repo_path)
            cleanup_mock.assert_called_once_with("smart-grid-repo")

    def test_build_checkout_error_message_explains_missing_branch(self):
        error = git.exc.GitCommandError(
            "git checkout baseline-clean",
            1,
            stderr="error: pathspec 'baseline-clean' did not match any file(s) known to git",
        )

        message = self.manager._build_checkout_error_message("baseline-clean", error)

        self.assertIn("Reference 'baseline-clean' was not found", message)
        self.assertIn("git push origin main baseline-clean suspicious-commit runtime-attackable", message)


if __name__ == "__main__":
    unittest.main()
