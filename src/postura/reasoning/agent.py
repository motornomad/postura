"""LangGraph security reasoning agent — P4.4

Implements a ReAct-style agent that uses the 6 POSTURA tools to reason about
security findings and produce PRSecurityReview objects.

The agent's reasoning chain for a PR review:
  1. Query the graph for new/changed findings in this commit
  2. For each high-severity finding, assess exploitability
  3. Retrieve relevant CWE/OWASP knowledge
  4. Trace dataflow from public endpoints to findings
  5. Find vulnerability chains
  6. Synthesize into a PRSecurityReview

Exported:
    run_pr_review(commit_sha, diff, pr_number) → PRSecurityReview
"""
from __future__ import annotations

import logging
from typing import Annotated, Any, Literal

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import tool
from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode
from pydantic import BaseModel
from typing_extensions import TypedDict

from postura.config import settings
from postura.models.findings import PRSecurityReview

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """You are POSTURA, an expert application security agent. You analyze code changes
and their impact on a live security threat graph to produce precise, evidence-based security reviews.

You have access to tools that let you:
- Query the Neo4j threat graph (graph_query)
- Retrieve CWE/CVE/OWASP security knowledge (knowledge_retrieve)
- Trace data flow paths (trace_dataflow)
- Find vulnerability chains (find_chains)
- Assess exploitability of findings (assess_exploitability)
- Generate remediation suggestions (generate_remediation)

Your job is to analyze findings introduced or affected by a commit and produce a structured
security review. Think step-by-step: start by querying the graph to understand what changed,
then investigate each significant finding in depth before drawing conclusions.

Focus on:
1. What new risks were introduced?
2. Are any new vulnerabilities chained (composing into higher-risk scenarios)?
3. What is the business impact (PII exposure, auth bypass, remote code execution)?
4. What specific remediations are required?

When you have completed your analysis, you MUST call the submit_review tool with your
structured findings. This is required — do not end your response with free text.
"""


# ---------------------------------------------------------------------------
# LangChain tool wrappers
# ---------------------------------------------------------------------------

from postura.reasoning.tools import (
    graph_query as _graph_query,
    knowledge_retrieve as _knowledge_retrieve,
    trace_dataflow as _trace_dataflow,
    find_chains as _find_chains,
    assess_exploitability as _assess_exploitability,
    generate_remediation as _generate_remediation,
)


@tool
def graph_query(cypher: str, params: dict | None = None) -> str:
    """Execute a read-only Cypher query against the Neo4j threat graph.
    Returns results as a formatted string."""
    rows = _graph_query(cypher, params)
    if not rows:
        return "No results."
    return "\n".join(str(row) for row in rows[:20])


@tool
def knowledge_retrieve(query: str, k: int = 5, sources: list[str] | None = None) -> str:
    """Retrieve relevant security knowledge from CWE/CVE/OWASP knowledge base.
    Returns formatted knowledge entries."""
    results = _knowledge_retrieve(query, k=k, sources=sources)
    if not results:
        return "No knowledge entries found."
    parts = []
    for r in results:
        parts.append(f"[{r['id']}] {r['document'][:500]}")
    return "\n\n".join(parts)


@tool
def trace_dataflow(start_uid: str, sink_type: str = "DataStore", max_hops: int = 6) -> str:
    """Trace call paths from a starting node to a sink. Returns path descriptions."""
    paths = _trace_dataflow(start_uid, sink_type, max_hops)
    if not paths:
        return "No paths found."
    return "\n".join(
        f"Path ({p['hops']} hops): {' → '.join(str(n) for n in p['path_nodes'])}"
        for p in paths[:10]
    )


@tool
def find_chains(finding_uid: str | None = None) -> str:
    """Find vulnerability chains (CHAINS_TO edges) for a finding or all findings."""
    chains = _find_chains(finding_uid)
    if not chains:
        return "No chains found."
    return "\n".join(
        f"CHAIN: [{c['from_title']}] → [{c['to_title']}] "
        f"(confidence={c.get('confidence', '?')}, evidence={c.get('evidence', '')})"
        for c in chains
    )


@tool
def assess_exploitability(finding_uid: str) -> str:
    """Assess exploitability of a finding — returns trust zone, reachability, PII exposure."""
    ctx = _assess_exploitability(finding_uid)
    if "error" in ctx:
        return ctx["error"]
    lines = [
        f"Finding: {ctx.get('title')} ({ctx.get('contextual_severity')})",
        f"Publicly reachable: {ctx.get('is_publicly_reachable')} via {ctx.get('reachable_via_endpoints', [])}",
        f"PII exposed: {ctx.get('exposes_pii')} — {ctx.get('pii_datastores', [])}",
        f"In chain: {ctx.get('in_chain')} ({ctx.get('outbound_chains')} outbound chains)",
        f"Trust zones: {ctx.get('trust_zones')}",
    ]
    return "\n".join(lines)


@tool
def generate_remediation(finding_uid: str, additional_context: str = "") -> str:
    """Generate a specific remediation suggestion for a finding using Claude."""
    result = _generate_remediation(finding_uid, additional_context)
    if "error" in result:
        return result["error"]
    return (
        f"REMEDIATION for {result.get('title')} ({result.get('cwe_id')}):\n"
        f"{result.get('remediation', '')}\n"
        f"References: {', '.join(result.get('references', []))}"
    )


# ---------------------------------------------------------------------------
# submit_review — structured final output tool (GAP 1 fix)
# ---------------------------------------------------------------------------

class _ReviewOutput(BaseModel):
    risk_level: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
    requires_block: bool
    top_issues: list[str]
    summary: str


@tool
def submit_review(
    risk_level: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"],
    requires_block: bool,
    top_issues: list[str],
    summary: str,
) -> str:
    """Submit the final structured security review. Call this as your last action
    after completing your analysis. This is how your assessment is recorded.

    Args:
        risk_level: Overall risk level: CRITICAL, HIGH, MEDIUM, LOW, or NONE.
        requires_block: True if this PR should be blocked from merging.
        top_issues: List of the top finding titles (max 5).
        summary: One-paragraph summary of the risk and required actions.
    """
    # The actual extraction happens in run_pr_review by inspecting tool call args.
    return f"Review submitted: {risk_level}"


_TOOLS = [
    graph_query, knowledge_retrieve, trace_dataflow,
    find_chains, assess_exploitability, generate_remediation,
    submit_review,
]


# ---------------------------------------------------------------------------
# LangGraph agent state + graph
# ---------------------------------------------------------------------------

class AgentState(TypedDict):
    messages: Annotated[list, add_messages]


def _should_continue(state: AgentState) -> Literal["tools", "end"]:
    last = state["messages"][-1]
    if isinstance(last, AIMessage) and last.tool_calls:
        # If the only tool call is submit_review, we're done
        tool_names = [tc["name"] for tc in last.tool_calls]
        if tool_names == ["submit_review"]:
            return "end"
        return "tools"
    return "end"


import functools


@functools.lru_cache(maxsize=1)
def _get_agent_graph() -> Any:
    return _build_agent_graph()


def _build_agent_graph() -> Any:
    llm = ChatAnthropic(
        model=settings.llm_model,
        api_key=settings.llm_api_key,
        max_tokens=4096,
    ).bind_tools(_TOOLS)

    def call_model(state: AgentState) -> AgentState:
        response = llm.invoke(state["messages"])
        return {"messages": [response]}

    tool_node = ToolNode(_TOOLS)

    graph = StateGraph(AgentState)
    graph.add_node("agent", call_model)
    graph.add_node("tools", tool_node)
    graph.set_entry_point("agent")
    graph.add_conditional_edges("agent", _should_continue, {"tools": "tools", "end": END})
    graph.add_edge("tools", "agent")

    return graph.compile()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_pr_review(
    commit_sha: str,
    diff_summary: str = "",
    pr_number: int | None = None,
    new_finding_uids: list[str] | None = None,
) -> PRSecurityReview:
    """
    Run the LangGraph agent to produce a PRSecurityReview for a commit.

    Args:
        commit_sha: The commit SHA being reviewed.
        diff_summary: Human-readable summary of what changed (from GraphDiff).
        pr_number: GitHub PR number if applicable.
        new_finding_uids: UIDs of newly introduced Finding nodes (from GraphDiff).

    Returns:
        PRSecurityReview with agent's assessment.
    """
    agent = _get_agent_graph()

    user_message = _build_review_prompt(commit_sha, diff_summary, pr_number, new_finding_uids)

    try:
        result = agent.invoke({
            "messages": [
                SystemMessage(content=_SYSTEM_PROMPT),
                HumanMessage(content=user_message),
            ]
        })
        final_message = result["messages"][-1]

        # Check if agent called submit_review (structured path)
        if isinstance(final_message, AIMessage) and final_message.tool_calls:
            for tc in final_message.tool_calls:
                if tc["name"] == "submit_review":
                    args = tc["args"]
                    return PRSecurityReview(
                        commit_sha=commit_sha,
                        pr_number=pr_number,
                        risk_level=args.get("risk_level", "UNKNOWN"),
                        requires_block=args.get("requires_block", False),
                        top_issues=args.get("top_issues", []),
                        full_analysis=args.get("summary", ""),
                        finding_count=len(args.get("top_issues", [])),
                    )

        # Fallback: parse free text (regex) if submit_review wasn't called
        analysis_text = (
            final_message.content
            if isinstance(final_message.content, str)
            else str(final_message.content)
        )
    except Exception as exc:
        logger.error("Agent invocation failed: %s", exc)
        analysis_text = f"Agent failed: {exc}"

    return _parse_review(analysis_text, commit_sha, pr_number)


def _build_review_prompt(
    commit_sha: str,
    diff_summary: str,
    pr_number: int | None,
    new_finding_uids: list[str] | None,
) -> str:
    parts = [f"Please perform a security review for commit {commit_sha[:8]}."]
    if pr_number:
        parts.append(f"This is PR #{pr_number}.")
    if diff_summary:
        parts.append(f"\nGraph diff summary:\n{diff_summary}")
    if new_finding_uids:
        parts.append(
            f"\nNew findings introduced (UIDs):\n" + "\n".join(f"  - {uid}" for uid in new_finding_uids)
        )
    parts.append(
        "\nSteps to follow:\n"
        "1. Use graph_query to get details on each new finding\n"
        "2. For CRITICAL/HIGH findings, use assess_exploitability\n"
        "3. Use find_chains to check for vulnerability chains\n"
        "4. Use knowledge_retrieve to enrich your understanding of each CWE\n"
        "5. Use trace_dataflow for publicly reachable findings\n"
        "6. When analysis is complete, call submit_review with your structured findings.\n"
        "   Do not output a free-text summary — use the submit_review tool."
    )
    return "\n".join(parts)


def _parse_review(
    analysis_text: str,
    commit_sha: str,
    pr_number: int | None,
) -> PRSecurityReview:
    """Extract structured fields from agent output and build PRSecurityReview."""
    import re as _re

    risk_match = _re.search(r"RISK_LEVEL:\s*(CRITICAL|HIGH|MEDIUM|LOW|NONE)", analysis_text, _re.IGNORECASE)
    risk_level = risk_match.group(1).upper() if risk_match else "UNKNOWN"

    block_match = _re.search(r"REQUIRES_BLOCK:\s*(YES|NO)", analysis_text, _re.IGNORECASE)
    requires_block = block_match.group(1).upper() == "YES" if block_match else False

    issues_match = _re.search(r"TOP_ISSUES:\s*(.+)", analysis_text, _re.IGNORECASE)
    top_issues = []
    if issues_match:
        top_issues = [s.strip() for s in issues_match.group(1).split(",") if s.strip()]

    # Build structured review
    return PRSecurityReview(
        commit_sha=commit_sha,
        pr_number=pr_number,
        risk_level=risk_level,
        requires_block=requires_block,
        top_issues=top_issues,
        full_analysis=analysis_text,
        finding_count=len(top_issues),
    )
