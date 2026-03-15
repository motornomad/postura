"""Tests for reasoning/agent.py — parse logic and mocked LLM invocation."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# _parse_review — regex fallback
# ---------------------------------------------------------------------------

def test_parse_review_extracts_risk_level():
    from postura.reasoning.agent import _parse_review
    text = "Analysis complete.\nRISK_LEVEL: HIGH\nTOP_ISSUES: SQLi, Missing auth\nREQUIRES_BLOCK: YES"
    review = _parse_review(text, "abc1234", pr_number=42)
    assert review.risk_level == "HIGH"
    assert review.requires_block is True
    assert "SQLi" in review.top_issues


def test_parse_review_case_insensitive():
    from postura.reasoning.agent import _parse_review
    text = "risk_level: critical\nrequires_block: yes\ntop_issues: XSS"
    review = _parse_review(text, "abc1234", pr_number=None)
    assert review.risk_level == "CRITICAL"
    assert review.requires_block is True


def test_parse_review_missing_fields_defaults():
    from postura.reasoning.agent import _parse_review
    review = _parse_review("No structured output here.", "abc1234", pr_number=None)
    assert review.risk_level == "UNKNOWN"
    assert review.requires_block is False
    assert review.top_issues == []


def test_parse_review_sets_commit_sha():
    from postura.reasoning.agent import _parse_review
    review = _parse_review("RISK_LEVEL: LOW", "deadbeef", pr_number=7)
    assert review.commit_sha == "deadbeef"
    assert review.pr_number == 7


# ---------------------------------------------------------------------------
# _build_review_prompt
# ---------------------------------------------------------------------------

def test_build_review_prompt_includes_sha():
    from postura.reasoning.agent import _build_review_prompt
    prompt = _build_review_prompt("abc12345", "2 files changed", pr_number=10, new_finding_uids=None)
    assert "abc12345" in prompt
    assert "PR #10" in prompt


def test_build_review_prompt_includes_finding_uids():
    from postura.reasoning.agent import _build_review_prompt
    prompt = _build_review_prompt("sha1", "", pr_number=None, new_finding_uids=["uid-1", "uid-2"])
    assert "uid-1" in prompt
    assert "uid-2" in prompt


def test_build_review_prompt_instructs_submit_review():
    from postura.reasoning.agent import _build_review_prompt
    prompt = _build_review_prompt("sha1", "", pr_number=None, new_finding_uids=None)
    assert "submit_review" in prompt


# ---------------------------------------------------------------------------
# run_pr_review — mocked LLM, structured path (submit_review tool call)
# ---------------------------------------------------------------------------

def _make_fake_tool_call(risk_level="HIGH", requires_block=True, top_issues=None, summary="Test summary"):
    """Build a fake AIMessage that contains a submit_review tool call."""
    from langchain_core.messages import AIMessage
    msg = AIMessage(content="")
    msg.tool_calls = [
        {
            "name": "submit_review",
            "args": {
                "risk_level": risk_level,
                "requires_block": requires_block,
                "top_issues": top_issues or ["SQLi finding"],
                "summary": summary,
            },
            "id": "call_abc",
        }
    ]
    return msg


def test_run_pr_review_structured_output():
    """run_pr_review should extract structured data from submit_review tool call."""
    fake_response = _make_fake_tool_call(risk_level="CRITICAL", requires_block=True, top_issues=["SQLi", "Missing auth"])

    with patch("postura.reasoning.agent._get_agent_graph") as mock_build:
        mock_agent = MagicMock()
        mock_agent.invoke.return_value = {"messages": [fake_response]}
        mock_build.return_value = mock_agent

        from postura.reasoning.agent import run_pr_review
        review = run_pr_review("deadbeef", "2 findings added", pr_number=5, new_finding_uids=["uid-1"])

    assert review.risk_level == "CRITICAL"
    assert review.requires_block is True
    assert "SQLi" in review.top_issues
    assert review.commit_sha == "deadbeef"
    assert review.pr_number == 5


def test_run_pr_review_fallback_on_no_submit_review():
    """If agent doesn't call submit_review, fallback regex parsing still works."""
    from langchain_core.messages import AIMessage
    fake_text_response = AIMessage(content="RISK_LEVEL: MEDIUM\nREQUIRES_BLOCK: NO\nTOP_ISSUES: Hardcoded secret")
    fake_text_response.tool_calls = []

    with patch("postura.reasoning.agent._get_agent_graph") as mock_build:
        mock_agent = MagicMock()
        mock_agent.invoke.return_value = {"messages": [fake_text_response]}
        mock_build.return_value = mock_agent

        from postura.reasoning.agent import run_pr_review
        review = run_pr_review("abc1234", "", pr_number=None)

    assert review.risk_level == "MEDIUM"
    assert review.requires_block is False


def test_run_pr_review_agent_exception_returns_unknown():
    """If agent raises, return UNKNOWN risk level gracefully."""
    with patch("postura.reasoning.agent._get_agent_graph") as mock_build:
        mock_agent = MagicMock()
        mock_agent.invoke.side_effect = RuntimeError("LLM timeout")
        mock_build.return_value = mock_agent

        from postura.reasoning.agent import run_pr_review
        review = run_pr_review("abc1234", "", pr_number=None)

    assert review.risk_level == "UNKNOWN"
    assert "Agent failed" in review.full_analysis
