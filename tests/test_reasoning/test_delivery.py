"""Unit tests for Phase 5 delivery layer — P5.1 + P5.2 + P5.3

Tests use mocks to avoid real GitHub API calls or Neo4j connections.
"""
from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock

from postura.models.findings import PRSecurityReview


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_review(
    risk_level: str = "HIGH",
    requires_block: bool = False,
    top_issues: list[str] | None = None,
    finding_count: int = 3,
    full_analysis: str = "Agent found SQL injection issues.",
    posture_delta: float = -5.0,
) -> PRSecurityReview:
    return PRSecurityReview(
        commit_sha="deadbeef1234abcd",
        pr_number=42,
        risk_level=risk_level,
        requires_block=requires_block,
        top_issues=top_issues or ["SQL Injection in db.py", "Missing auth on /admin/users"],
        finding_count=finding_count,
        full_analysis=full_analysis,
        posture_delta=posture_delta,
        posture_change="DEGRADED" if posture_delta > 0 else "IMPROVED",
    )


# ---------------------------------------------------------------------------
# PR comment formatting
# ---------------------------------------------------------------------------

class TestPRCommentFormatting:
    def test_comment_contains_risk_level(self):
        from postura.delivery.github import _format_pr_comment
        comment = _format_pr_comment(_make_review(risk_level="CRITICAL"))
        assert "CRITICAL" in comment

    def test_comment_contains_commit_sha(self):
        from postura.delivery.github import _format_pr_comment
        comment = _format_pr_comment(_make_review())
        assert "deadbeef" in comment

    def test_block_warning_shown_when_required(self):
        from postura.delivery.github import _format_pr_comment
        comment = _format_pr_comment(_make_review(requires_block=True))
        assert "blocked" in comment.lower() or "⛔" in comment

    def test_no_block_warning_when_not_required(self):
        from postura.delivery.github import _format_pr_comment
        comment = _format_pr_comment(_make_review(requires_block=False))
        assert "⛔" not in comment

    def test_top_issues_listed(self):
        from postura.delivery.github import _format_pr_comment
        comment = _format_pr_comment(_make_review())
        assert "SQL Injection" in comment
        assert "Missing auth" in comment

    def test_full_analysis_truncated_at_2000(self):
        from postura.delivery.github import _format_pr_comment
        long_analysis = "x" * 3000
        comment = _format_pr_comment(_make_review(full_analysis=long_analysis))
        assert "truncated" in comment

    def test_none_risk_shows_green(self):
        from postura.delivery.github import _format_pr_comment
        comment = _format_pr_comment(_make_review(risk_level="NONE", finding_count=0, top_issues=[]))
        assert "✅" in comment or "NONE" in comment


# ---------------------------------------------------------------------------
# Commit status mapping
# ---------------------------------------------------------------------------

class TestCommitStatusMapping:
    def test_failure_when_block_required(self):
        from postura.delivery.github import _review_to_status
        state, desc = _review_to_status(_make_review(requires_block=True))
        assert state == "failure"
        assert "blocked" in desc.lower()

    def test_failure_for_critical_no_block(self):
        from postura.delivery.github import _review_to_status
        state, desc = _review_to_status(_make_review(risk_level="CRITICAL", requires_block=False))
        assert state == "failure"

    def test_pending_for_medium(self):
        from postura.delivery.github import _review_to_status
        state, desc = _review_to_status(_make_review(risk_level="MEDIUM", requires_block=False))
        assert state == "pending"

    def test_success_for_low(self):
        from postura.delivery.github import _review_to_status
        state, desc = _review_to_status(_make_review(risk_level="LOW", requires_block=False))
        assert state == "success"

    def test_success_for_none(self):
        from postura.delivery.github import _review_to_status
        state, _ = _review_to_status(_make_review(risk_level="NONE", requires_block=False))
        assert state == "success"

    def test_description_truncated(self):
        from postura.delivery.github import _review_to_status
        _, desc = _review_to_status(_make_review())
        assert len(desc) <= 140


# ---------------------------------------------------------------------------
# GitHub API calls (mocked)
# ---------------------------------------------------------------------------

class TestGitHubDelivery:
    def test_post_pr_comment_skipped_without_token(self, monkeypatch):
        monkeypatch.setattr("postura.config.settings.github_token", "")
        from postura.delivery.github import post_pr_comment
        result = post_pr_comment("owner/repo", 42, _make_review())
        assert result is None

    def test_set_commit_status_skipped_without_token(self, monkeypatch):
        monkeypatch.setattr("postura.config.settings.github_token", "")
        from postura.delivery.github import set_commit_status
        result = set_commit_status("owner/repo", "deadbeef", _make_review())
        assert result is None

    def test_post_pr_comment_calls_api(self, monkeypatch):
        monkeypatch.setattr("postura.config.settings.github_token", "test-token")
        mock_resp = {"html_url": "https://github.com/owner/repo/pull/42#issuecomment-1"}

        with patch("postura.delivery.github._gh_post", return_value=mock_resp) as mock_post:
            from postura.delivery import github
            # Force reload to pick up monkeypatched token
            result = github.post_pr_comment("owner/repo", 42, _make_review())

        assert result == "https://github.com/owner/repo/pull/42#issuecomment-1"

    def test_set_commit_status_calls_api(self, monkeypatch):
        monkeypatch.setattr("postura.config.settings.github_token", "test-token")
        mock_resp = {"url": "https://api.github.com/repos/owner/repo/statuses/deadbeef"}

        with patch("postura.delivery.github._gh_post", return_value=mock_resp):
            from postura.delivery import github
            result = github.set_commit_status("owner/repo", "deadbeef1234", _make_review())

        assert "statuses" in result

    def test_gh_post_returns_none_on_http_error(self, monkeypatch):
        monkeypatch.setattr("postura.config.settings.github_token", "test-token")
        with patch("requests.post") as mock_post:
            import requests
            mock_response = MagicMock()
            mock_response.status_code = 403
            mock_response.text = "Forbidden"
            mock_post.return_value = mock_response
            mock_response.raise_for_status.side_effect = requests.HTTPError(response=mock_response)

            from postura.delivery.github import _gh_post
            result = _gh_post("https://api.github.com/test", {})
            assert result is None


# ---------------------------------------------------------------------------
# Posture history (mocked Neo4j)
# ---------------------------------------------------------------------------

class TestPostureHistory:
    def test_record_snapshot_calls_run_write(self):
        with patch("postura.delivery.history.run_write") as mock_write:
            from postura.delivery.history import record_snapshot
            snapshot = record_snapshot(
                commit_sha="abc123",
                score=72.5,
                finding_counts={"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3},
                chain_count=2,
                repo="owner/repo",
                posture_change="DEGRADED",
            )
        assert mock_write.called
        assert snapshot.commit_sha == "abc123"
        assert snapshot.score == 72.5
        assert snapshot.chain_count == 2

    def test_get_posture_history_returns_rows(self):
        mock_rows = [
            {"commit_sha": "abc", "score": 80.0, "timestamp": "2026-03-01T00:00:00Z",
             "chain_count": 1, "posture_change": "IMPROVED", "critical_count": 0,
             "high_count": 1, "medium_count": 2, "low_count": 0, "repo": "o/r", "pr_number": None},
        ]
        with patch("postura.delivery.history.run_query", return_value=mock_rows):
            from postura.delivery.history import get_posture_history
            history = get_posture_history(limit=10)
        assert len(history) == 1
        assert history[0]["commit_sha"] == "abc"

    def test_trend_improving(self):
        snapshots = [
            {"score": 90.0, "commit_sha": "new"},
            {"score": 70.0, "commit_sha": "old"},
        ]
        with patch("postura.delivery.history.get_posture_history", return_value=snapshots):
            from postura.delivery.history import get_posture_trend
            trend = get_posture_trend(window=2)
        assert trend["trend"] == "improving"
        assert trend["delta"] == 20.0

    def test_trend_degrading(self):
        snapshots = [
            {"score": 50.0, "commit_sha": "new"},
            {"score": 80.0, "commit_sha": "old"},
        ]
        with patch("postura.delivery.history.get_posture_history", return_value=snapshots):
            from postura.delivery.history import get_posture_trend
            trend = get_posture_trend(window=2)
        assert trend["trend"] == "degrading"
        assert trend["delta"] == -30.0

    def test_trend_stable(self):
        snapshots = [
            {"score": 80.0, "commit_sha": "new"},
            {"score": 79.5, "commit_sha": "old"},
        ]
        with patch("postura.delivery.history.get_posture_history", return_value=snapshots):
            from postura.delivery.history import get_posture_trend
            trend = get_posture_trend(window=2)
        assert trend["trend"] == "stable"

    def test_trend_empty_history(self):
        with patch("postura.delivery.history.get_posture_history", return_value=[]):
            from postura.delivery.history import get_posture_trend
            trend = get_posture_trend()
        assert trend["trend"] == "unknown"


# ---------------------------------------------------------------------------
# PRSecurityReview model
# ---------------------------------------------------------------------------

class TestPRSecurityReviewModel:
    def test_default_fields(self):
        review = PRSecurityReview(commit_sha="abc123")
        assert review.risk_level == "UNKNOWN"
        assert review.requires_block is False
        assert review.top_issues == []
        assert review.full_analysis == ""

    def test_serialization(self):
        review = _make_review()
        data = review.model_dump()
        assert data["commit_sha"] == "deadbeef1234abcd"
        assert data["risk_level"] == "HIGH"
        assert data["requires_block"] is False
        assert len(data["top_issues"]) == 2
