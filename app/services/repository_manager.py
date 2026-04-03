import os
import shutil
import git
import stat
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Any, List
from app.core.config import settings
from app.core.exceptions import RepositoryError, AnalysisError
from antlr_detection.handleListeners.HandleListeners import AntlrListenerHandler
from app.utilities.logger import logger


class RepositoryManager:
    """
    Manage operations about Git repositories (clone, update, cleanup)
    and orchestrate static analysis.
    """
    def __init__(self) -> None:
        self.cloned_repos_base_dir: Path = settings.CLONED_REPOS_BASE_DIR
        self.antlr_handler: AntlrListenerHandler = AntlrListenerHandler()


    def _get_repo_path(self, repo_name: str) -> Path:
        """Build the local path for cloned repositories."""
        return self.cloned_repos_base_dir / repo_name

    def get_repo_path(self, repo_name: str) -> Path:
        """Public accessor for local repository path."""
        return self._get_repo_path(repo_name)

    def _normalize_repo_source(self, repo_url: str) -> str:
        """Normalize local and remote repository references so we can compare origins safely."""
        normalized = repo_url.strip().rstrip("/")
        if normalized.endswith(".git"):
            normalized = normalized[:-4]

        possible_path = Path(normalized)
        if possible_path.exists():
            return possible_path.resolve().as_posix().lower()

        return normalized.lower()

    def _is_valid_git_repository(self, repo_path: Path) -> bool:
        """Return whether a local path contains a readable Git repository."""
        try:
            git.Repo(repo_path)
            return True
        except (git.exc.InvalidGitRepositoryError, git.exc.NoSuchPathError):  # type: ignore
            return False

    def _repo_origin_matches(self, repo_path: Path, repo_url: str) -> bool:
        """Compare the local origin against the requested source URL/path."""
        try:
            repo = git.Repo(repo_path)
            origin = repo.remotes.origin
            origin_urls = list(origin.urls)
            if not origin_urls:
                return False
            return self._normalize_repo_source(origin_urls[0]) == self._normalize_repo_source(repo_url)
        except Exception:
            return False

    def _prepare_repository_target(self, repo_url: str, repo_name: str) -> Path:
        """
        Ensure the target folder is usable for the requested source.
        If the folder contains an invalid repository or points to a different origin, re-clone it.
        """
        repo_path = self._get_repo_path(repo_name)
        if not repo_path.exists():
            return repo_path

        if not self._is_valid_git_repository(repo_path):
            logger.warning(
                f"Repository path '{repo_path}' exists but is not a valid Git repository. Recreating it."
            )
            self.cleanup_repository(repo_name)
            return repo_path

        if not self._repo_origin_matches(repo_path, repo_url):
            logger.info(
                f"Repository '{repo_name}' exists with a different origin. Re-cloning from '{repo_url}'."
            )
            self.cleanup_repository(repo_name)

        return repo_path

    def _build_clone_error_message(self, repo_url: str, error: git.exc.GitCommandError) -> str:  # type: ignore
        """Return a friendlier clone error for known Git issues used during demos."""
        error_text = str(error)
        if "detected dubious ownership" in error_text:
            return (
                "Git blocked access to the repository because the local '.git' directory belongs to a different "
                "Windows user. For VESTA demos, prefer using a remote GitHub URL instead of a local repository path. "
                "If you intentionally need the local path, mark it as safe with "
                "'git config --global --add safe.directory <repo>/.git' and retry."
            )
        return f"Error executing Git command to clone: {error}"

    def _build_checkout_error_message(self, reference: str, error: git.exc.GitCommandError) -> str:  # type: ignore
        """Return a friendlier checkout error when users pass branches/tags in the commit field."""
        error_text = str(error)
        if "pathspec" in error_text and "did not match any file(s) known to git" in error_text:
            return (
                f"Reference '{reference}' was not found in the repository. "
                "If you are using a branch for the VESTA demo, make sure it has been pushed to GitHub "
                "(for example: `git push origin main baseline-clean suspicious-commit runtime-attackable`)."
            )
        return f"Error executing Git command for checkout: {error}"

    def _checkout_reference(self, repo: git.Repo, reference: str) -> None:
        """
        Checkout a branch, tag, or commit. If the reference only exists on origin,
        create/reset a local branch from the remote ref.
        """
        try:
            repo.git.checkout(reference)
            return
        except git.exc.GitCommandError:
            pass

        origin = repo.remotes.origin
        origin.fetch(prune=True, tags=True)

        remote_ref_name = f"origin/{reference}"
        remote_refs = {ref.name: ref for ref in origin.refs}
        if remote_ref_name in remote_refs:
            if reference in repo.heads:
                repo.git.checkout(reference)
                repo.git.reset("--hard", remote_ref_name)
            else:
                repo.git.checkout("-B", reference, remote_ref_name)
            return

        try:
            repo.git.checkout(reference)
        except git.exc.GitCommandError as error:  # type: ignore
            raise RepositoryError(self._build_checkout_error_message(reference=reference, error=error))

    def _clone_repository(self, repo_url: str, repo_name: str, commit_hash: str|None = None) -> Path:
        """
        Clone a Git repository in the working directory.
        It can clone a specific version if commit_hash is provided.
        """
        repo_path: Path = self._get_repo_path(repo_name)

        if repo_path.exists():
            logger.error(f"The directory '{repo_name}' already exists in '{self.cloned_repos_base_dir}'.")
            raise RepositoryError(f"The directory '{repo_name}' already exists in '{self.cloned_repos_base_dir}'.")
        
        try:
            logger.info(f"Repository cloned '{repo_url}' in '{repo_path}'...")
            repo = git.Repo.clone_from(repo_url, repo_path)
            if commit_hash:
                logger.info(f"Checkout to the specific commit: {commit_hash}")
                self._checkout_reference(repo, commit_hash)
            logger.info("Repository has been cloned succesfully.")
            return repo_path
        except RepositoryError:
            raise
        except git.exc.GitCommandError as e:  # type: ignore
            logger.error(f"Git command error during cloning: {e}")
            raise RepositoryError(self._build_clone_error_message(repo_url=repo_url, error=e))
        except Exception as e:
            logger.error(f"Unexpected error during cloning: {e}")
            raise RepositoryError(f"Unexpected Error cloning repository: {e}")

    def _update_head_repository(self, repo_name: str, commit_hash: str|None = None) -> Path:
        """
        Update a Git repository in the working directory or make a checkout to a specific commit, 
        moving head to a specific commit or pull to get the latest changes from the remote tracking branch.
        """
        repo_path: Path = self._get_repo_path(repo_name)
        if not repo_path.exists():
            logger.error(f"Repository '{repo_name}' doesn't exist in a local folder. Clone it first.")
            raise RepositoryError(f"Repository '{repo_name}' doesn't exist in a local folder. Clone it first.")
        
        try:
            repo = git.Repo(repo_path)
            origin = repo.remotes.origin
            # Fetch all branches and tags
            origin.fetch()

            if commit_hash:
                # Checkout to the specific commit
                logger.info(f"Update repository '{repo_name}' and checkout to the specific commit: {commit_hash}...")
                self._checkout_reference(repo, commit_hash)
            else:
                # Pull the latest changes from the remote tracking branch
                default_branch_name = 'main' # 'main' default
                if 'main' not in repo.heads:
                    # If not exists main, try master
                    if 'master' in repo.heads:
                        default_branch_name = 'master'
                    else:
                        # If not exists a tipical branch the logic may be more complex
                        logger.error(f"Neither 'main' nor 'master' branches exist in the repository '{repo_name}'. Cannot perform pull operation.")
                        raise RepositoryError("Not is possible update the HEAD to main or master branch, please delete repository and clone again.")
                if repo.head.is_detached:
                    logger.info(f"HEAD is in 'detached'. Moving to branch '{default_branch_name}'...")
                    repo.heads[default_branch_name].checkout()

                logger.info(f"Update repository '{repo_name}' (pull)...")
                origin.pull() # Update current branch
            
            logger.info(f"Repository '{repo_name}' update succesfully.")
            return repo_path
        except RepositoryError:
            raise
        except git.exc.GitCommandError as e: # type: ignore
            logger.error(f"Git command error during pull/checkout: {e}")
            raise RepositoryError(f"Error executing Git command for pull/checkout: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during pull/checkout: {e}")
            raise RepositoryError(f"Unexpected error updating or moving head repository: {e}")

    def process_repository(self, repo_url: str, repo_name: str, commit_hash: str | None = None) -> List[Dict[str, Any]]:
        """
        Processes a Repository: clones if not exists, updates and make checkout if exists, and then analyzes.

        Args:
            repo_url (str): Repository Git URL.
            repo_name (str): Folder name for the local repository.
            commit_hash (str): Commit hash to do checkout.

        Returns:
            List[Dict[str, Any]]: List of analyze reports for each file.
        """
        repo_path: Path = self._prepare_repository_target(repo_url=repo_url, repo_name=repo_name)
        
        if not repo_path.exists():
            # If not exists, we clone it.
            cloned_path = self._clone_repository(repo_url, repo_name, commit_hash)
        else:
            # If exists, we update and make checkout to the commit.
            cloned_path = self._update_head_repository(repo_name, commit_hash)
        
        # Once the repository is in correct state, analyze it.
        reports = self.analyze_repository_code(cloned_path)
        return reports

    def analyze_repository_code(self, repo_path: Path) -> List[Dict[str, Any]]:
        """
        Analyze every code file supported in a repository cloned using AntlrListenerHandler.
        """
        if not repo_path.is_dir():
            logger.error(f"The provided path '{repo_path}' isn't a valid directory for analysis.")
            raise AnalysisError(f"The provided path '{repo_path}' isn't a valid directory for analysis.")
        
        logger.info(f"Start analyzing static code for the repository located in: {repo_path}")
        reports = self.antlr_handler.analyze_directory(str(repo_path))
        logger.info(f"Code static analysis completed for {len(reports)} files.")
        return reports

    def cleanup_repository(self, repo_name: str) -> None:
        """Delete repository that has been cloned locally with robust error handling."""
        repo_path: Path = self._get_repo_path(repo_name)
        if not repo_path.exists():
            print(f"Repository {repo_name} not found locally.")
            return
        logger.info(f"Deleting local repository: {repo_path}")
        print(f"Deleting local repository: {repo_path}")
        
        def handle_remove_readonly(func, path, exc):
            """Error handler for shutil.rmtree to handle readonly files."""
            if os.path.exists(path):
                # Change permissions
                os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
                # Try again
                func(path)
        
        try:
            shutil.rmtree(repo_path, onerror=handle_remove_readonly)
            logger.info("Repository was deleted successfully.")
        except Exception as e:
            logger.error(f"Standard deletion failed: {e}")
            # Fallback Method: force deletion
            try:
                self._force_delete_repository(repo_path)
                logger.info("Repository was deleted successfully with force method.")
            except Exception as e2:
                logger.error(f"Force deletion also failed: {e2}")
                # Last resort: rename the directory
                try:
                    backup_path = repo_path.with_suffix('.to_delete')
                    repo_path.rename(backup_path)
                    logger.warning(f"Repository renamed to {backup_path} for manual deletion.")
                    print("Please delete this directory manually when possible.")
                except Exception as e3:
                    print(f"All deletion methods failed: {e3}")
                    print("You will need to delete the repository manually.")

    def _force_delete_repository(self, repo_path: Path) -> None:
        """Force delete repository using multiple attempts and permission changes."""
        max_attempts = 3
        
        for attempt in range(max_attempts):
            try:
                for root, dirs, files in os.walk(repo_path):
                    for dir_name in dirs:
                        dir_path = os.path.join(root, dir_name)
                        try:
                            os.chmod(dir_path, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
                        except (OSError, PermissionError):
                            pass
                    
                    for file_name in files:
                        file_path = os.path.join(root, file_name)
                        try:
                            os.chmod(file_path, stat.S_IWRITE | stat.S_IREAD)
                        except (OSError, PermissionError):
                            pass
                
                # Try delete teh directory completly
                shutil.rmtree(repo_path)
                return
                
            except (OSError, PermissionError) as e:
                if attempt < max_attempts - 1:
                    logger.warning(f"Deletion attempt {attempt + 1} failed, retrying in 1 second...")
                    time.sleep(1)
                else:
                    raise Exception(f"Failed to delete repository after {max_attempts} attempts: {e}")

    @contextmanager
    def temporary_repository(self, repo_url: str, repo_name: str, commit_hash: str | None = None):
        """
        Context manager that automatically processes and cleans up repository.
        
        Usage:
            with repo_manager.temporary_repository(url, name) as reports:
                # Use reports here
                pass
            # Repository is automatically cleaned up
        """
        try:
            # Procesar el repositorio
            reports = self.process_repository(repo_url, repo_name, commit_hash)
            yield reports
        finally:
            # Cleanup automático al salir del context manager
            self.cleanup_repository(repo_name)


if __name__ == "__main__":
    import json

    repo_manager = RepositoryManager()
    url_repo = "https://github.com/JuanSebastianFernandez/GenSQLDatasets"
    repo_name = "GenSQLDatasets"
    commit_hash = "84f033dd15ffbcfaf33ab7937ba0fba2418229a2"
    
    # reports = repo_manager.process_repository(repo_url=url_repo, repo_name=repo_name)
    # for report in reports:
    #     if report["status"] == "SUCCESS":
    #         print(json.dumps(report, indent=4, ensure_ascii=False))
    #         print("\n-------------------------------------------------\n")
    
    # repo_manager.cleanup_repository(repo_name=repo_name)

    with repo_manager.temporary_repository(repo_url=url_repo, repo_name=repo_name, commit_hash=commit_hash) as reports:
        for report in reports:
            if report["status"] == "SUCCESS":
                print(json.dumps(report, indent=4, ensure_ascii=False))
                print("\n-------------------------------------------------\n")
