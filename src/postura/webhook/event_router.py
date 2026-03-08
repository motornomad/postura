"""Event router — P3.1b

Parses GitHub webhook payloads, classifies event type, extracts metadata.
Returns a structured WebhookEvent or None if the event is non-actionable.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# File patterns that indicate security-relevant changes
_SECURITY_SENSITIVE_PATTERNS = [
    "requirements", "pyproject.toml", "setup.cfg", "setup.py",
    "Pipfile", "Pipfile.lock", "poetry.lock",
    ".env", "config", "auth", "security", "middleware",
    "settings", "secrets", "credentials",
]


@dataclass
class WebhookEvent:
    event_type: str                         # "push" | "pull_request"
    commit_sha: str
    repo_full_name: str                     # "owner/repo"
    clone_url: str
    branch: str
    changed_files: list[str] = field(default_factory=list)
    pr_number: Optional[int] = None
    is_security_relevant: bool = False
    action: Optional[str] = None           # for PR: "opened", "synchronize", etc.


def route_event(event_type: str, payload: dict) -> Optional[WebhookEvent]:
    """
    Parse a GitHub webhook payload and return a WebhookEvent, or None if non-actionable.

    Supported events:
    - push
    - pull_request (opened, synchronize, reopened)
    """
    if event_type == "push":
        return _handle_push(payload)
    elif event_type == "pull_request":
        return _handle_pull_request(payload)
    elif event_type == "ping":
        logger.info("Received ping from GitHub — webhook configured correctly")
        return None
    else:
        logger.debug("Ignoring unsupported event type: %s", event_type)
        return None


def _handle_push(payload: dict) -> Optional[WebhookEvent]:
    """Parse a push event payload."""
    repo = payload.get("repository", {})
    commits = payload.get("commits", [])

    if not commits:
        return None  # empty push (e.g., branch creation without commits)

    # Use the HEAD commit SHA
    head_commit = payload.get("head_commit") or commits[-1]
    commit_sha = payload.get("after") or head_commit.get("id", "")

    if not commit_sha or commit_sha == "0" * 40:
        return None  # branch deletion

    # Collect changed files across all commits
    changed_files: set[str] = set()
    for commit in commits:
        changed_files.update(commit.get("added", []))
        changed_files.update(commit.get("modified", []))
        changed_files.update(commit.get("removed", []))

    branch = payload.get("ref", "").replace("refs/heads/", "")

    event = WebhookEvent(
        event_type="push",
        commit_sha=commit_sha,
        repo_full_name=repo.get("full_name", ""),
        clone_url=repo.get("clone_url", ""),
        branch=branch,
        changed_files=sorted(changed_files),
        is_security_relevant=_is_security_relevant(list(changed_files)),
    )
    logger.info(
        "Push event: %s@%s — %d files changed",
        event.repo_full_name, commit_sha[:8], len(changed_files),
    )
    return event


def _handle_pull_request(payload: dict) -> Optional[WebhookEvent]:
    """Parse a pull_request event payload."""
    action = payload.get("action", "")
    if action not in ("opened", "synchronize", "reopened"):
        return None  # ignore close, label, etc.

    pr = payload.get("pull_request", {})
    repo = payload.get("repository", {})

    commit_sha = pr.get("head", {}).get("sha", "")
    pr_number = payload.get("number")
    branch = pr.get("head", {}).get("ref", "")

    # For PRs, we don't have the file list in the webhook payload —
    # we'll compute it from git diff in the scope analyzer
    event = WebhookEvent(
        event_type="pull_request",
        commit_sha=commit_sha,
        repo_full_name=repo.get("full_name", ""),
        clone_url=repo.get("clone_url", ""),
        branch=branch,
        changed_files=[],  # populated by scope analyzer from git diff
        pr_number=pr_number,
        is_security_relevant=True,  # always analyze PRs
        action=action,
    )
    logger.info(
        "PR event: %s #%s (%s) — SHA %s",
        event.repo_full_name, pr_number, action, commit_sha[:8],
    )
    return event


def _is_security_relevant(changed_files: list[str]) -> bool:
    """Heuristic: are any changed files security-sensitive?"""
    for f in changed_files:
        f_lower = f.lower()
        if f_lower.endswith(".py"):
            return True  # all Python changes are relevant
        if any(pattern in f_lower for pattern in _SECURITY_SENSITIVE_PATTERNS):
            return True
    return False
