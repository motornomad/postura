"""Unit tests for webhook event routing and scope analysis."""
import pytest
from postura.webhook.event_router import route_event, _is_security_relevant


class TestEventRouter:
    def test_push_event_parsed(self):
        payload = {
            "after": "abc123def456",
            "ref": "refs/heads/main",
            "repository": {
                "full_name": "owner/repo",
                "clone_url": "https://github.com/owner/repo.git",
            },
            "commits": [
                {
                    "id": "abc123def456",
                    "added": ["src/auth.py"],
                    "modified": ["src/app.py"],
                    "removed": [],
                }
            ],
            "head_commit": {"id": "abc123def456"},
        }
        event = route_event("push", payload)
        assert event is not None
        assert event.commit_sha == "abc123def456"
        assert event.event_type == "push"
        assert event.branch == "main"
        assert "src/auth.py" in event.changed_files
        assert "src/app.py" in event.changed_files

    def test_pull_request_event_parsed(self):
        payload = {
            "action": "opened",
            "number": 42,
            "pull_request": {
                "head": {"sha": "deadbeef1234", "ref": "feature/sqli-fix"},
            },
            "repository": {
                "full_name": "owner/repo",
                "clone_url": "https://github.com/owner/repo.git",
            },
        }
        event = route_event("pull_request", payload)
        assert event is not None
        assert event.commit_sha == "deadbeef1234"
        assert event.pr_number == 42
        assert event.action == "opened"

    def test_ping_event_returns_none(self):
        assert route_event("ping", {}) is None

    def test_pr_close_ignored(self):
        payload = {"action": "closed", "number": 1,
                   "pull_request": {"head": {"sha": "abc", "ref": "x"}},
                   "repository": {"full_name": "o/r", "clone_url": ""}}
        assert route_event("pull_request", payload) is None

    def test_push_branch_deletion_ignored(self):
        payload = {
            "after": "0" * 40,
            "ref": "refs/heads/feature",
            "repository": {"full_name": "o/r", "clone_url": ""},
            "commits": [],
        }
        event = route_event("push", payload)
        assert event is None

    def test_security_relevance_python_files(self):
        assert _is_security_relevant(["src/auth.py"]) is True
        assert _is_security_relevant(["README.md"]) is False
        assert _is_security_relevant(["requirements.txt"]) is True
        assert _is_security_relevant(["config/settings.py"]) is True


class TestScopeAnalyzer:
    def test_file_categorization(self):
        from postura.webhook.scope_analyzer import _categorize_files
        code, deps, config = _categorize_files([
            "src/app.py", "requirements.txt", "config/settings.py", "README.md"
        ])
        assert "src/app.py" in code
        assert "requirements.txt" in deps
        assert "config/settings.py" in config

    def test_change_scope_all_affected(self):
        from postura.webhook.scope_analyzer import ChangeScope
        scope = ChangeScope(
            commit_sha="abc123",
            changed_code_files=["src/auth.py"],
            transitive_dependents=["src/app.py"],
        )
        affected = scope.all_affected_files
        assert "src/auth.py" in affected
        assert "src/app.py" in affected
        # No duplicates
        assert len(affected) == len(set(affected))
