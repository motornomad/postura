"""Repo checkout manager — P3.3a

Clones and maintains local copies of repos for analysis.
Supports checkout to specific SHAs.
"""
from __future__ import annotations

import logging
import shutil
import tempfile
from pathlib import Path
from typing import Optional

import git

logger = logging.getLogger(__name__)

# Cache dir: reuse clones across analysis runs
_CLONE_CACHE_DIR = Path(tempfile.gettempdir()) / "postura_repos"


class RepoManager:
    """
    Manages local clones of repositories.

    Caches clones under _CLONE_CACHE_DIR/<owner>/<repo>/.
    Fetches and checks out the requested SHA on each call.
    """

    def __init__(self, cache_dir: Optional[Path] = None) -> None:
        self.cache_dir = cache_dir or _CLONE_CACHE_DIR
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def get_repo_at_commit(self, clone_url: str, commit_sha: str) -> str:
        """
        Clone (or fetch) the repo and checkout the given commit SHA.
        Returns the local path to the checked-out repo.
        """
        repo_path = self._clone_path(clone_url)

        if repo_path.exists():
            repo = self._fetch_and_checkout(repo_path, commit_sha)
        else:
            repo = self._clone_and_checkout(clone_url, repo_path, commit_sha)

        return str(repo_path)

    def cleanup(self, clone_url: str) -> None:
        """Remove the local clone for a repo."""
        repo_path = self._clone_path(clone_url)
        if repo_path.exists():
            shutil.rmtree(repo_path)
            logger.info("Cleaned up clone: %s", repo_path)

    def _clone_path(self, clone_url: str) -> Path:
        """Derive a stable local path from the clone URL."""
        # Extract owner/repo from URL: https://github.com/owner/repo.git
        clean = clone_url.rstrip("/").rstrip(".git")
        parts = clean.split("/")
        if len(parts) >= 2:
            owner, repo = parts[-2], parts[-1]
        else:
            owner, repo = "unknown", parts[-1]
        return self.cache_dir / owner / repo

    def _clone_and_checkout(
        self, clone_url: str, repo_path: Path, commit_sha: str
    ) -> git.Repo:
        """Fresh clone and checkout."""
        repo_path.parent.mkdir(parents=True, exist_ok=True)
        logger.info("Cloning %s → %s", clone_url, repo_path)
        try:
            repo = git.Repo.clone_from(clone_url, str(repo_path))
            repo.git.checkout(commit_sha)
            logger.info("Checked out %s", commit_sha[:8])
            return repo
        except git.GitCommandError as e:
            logger.error("Failed to clone %s: %s", clone_url, e)
            raise

    def _fetch_and_checkout(self, repo_path: Path, commit_sha: str) -> git.Repo:
        """Fetch latest and checkout the requested SHA."""
        try:
            repo = git.Repo(str(repo_path))
            # Check if SHA is already available
            try:
                repo.commit(commit_sha)
            except git.BadName:
                # SHA not found locally — fetch
                logger.info("Fetching new commits for %s", repo_path)
                repo.remotes.origin.fetch()
            repo.git.checkout(commit_sha)
            logger.info("Checked out %s in existing clone", commit_sha[:8])
            return repo
        except git.GitCommandError as e:
            logger.warning("Checkout failed (%s), re-cloning: %s", commit_sha[:8], e)
            shutil.rmtree(repo_path)
            raise  # caller should re-clone


# Module-level singleton
_manager = RepoManager()


def get_repo_at_commit(clone_url: str, commit_sha: str) -> str:
    """Convenience function: clone/fetch and checkout a commit. Returns local path."""
    return _manager.get_repo_at_commit(clone_url, commit_sha)
