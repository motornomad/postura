"""Graph diff computation — P3.4c

Computes GraphDiff from pre/post subgraph snapshots.
Re-runs chain discovery and severity scoring on the affected subgraph.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from postura.graph.connection import run_query
from postura.models.findings import GraphDiff
from postura.reasoning.chain_discovery import discover_chains
from postura.reasoning.severity_scorer import score_all_findings, compute_posture_score

logger = logging.getLogger(__name__)


def compute_graph_diff(
    commit_sha: str,
    pre_uids: set[str],
    post_uids: set[str],
    prev_posture_score: float,
) -> GraphDiff:
    """
    Compare pre-update vs post-update subgraph state.
    Re-runs chain discovery and severity scoring on the affected area.
    Returns a GraphDiff.
    """
    # Re-run chain discovery (finds new or broken chains in whole graph)
    discover_chains()

    # Re-run severity scoring
    score_all_findings()

    # Compute new posture score
    new_score = compute_posture_score()
    posture_delta = prev_posture_score - new_score  # positive = degraded

    # Compute node diffs
    new_node_uids = post_uids - pre_uids
    removed_node_uids = pre_uids - post_uids
    common_uids = pre_uids & post_uids

    # Fetch new nodes
    new_nodes = _fetch_nodes_by_uids(new_node_uids) if new_node_uids else []
    removed_nodes = [{"uid": uid} for uid in removed_node_uids]
    changed_nodes = _find_changed_nodes(common_uids, commit_sha)

    # Fetch new/broken chains (CHAINS_TO edges involving affected nodes)
    new_chains, broken_chains = _diff_chains(pre_uids, post_uids)

    # Build summary
    summary = _build_summary(
        new_nodes=new_nodes,
        removed_nodes=removed_nodes,
        new_chains=new_chains,
        posture_delta=posture_delta,
        new_score=new_score,
    )

    diff = GraphDiff(
        commit_sha=commit_sha,
        new_nodes=new_nodes,
        removed_nodes=removed_nodes,
        changed_nodes=changed_nodes,
        new_edges=[],   # edge-level diff omitted for now (costly to compute)
        removed_edges=[],
        new_chains=new_chains,
        broken_chains=broken_chains,
        posture_delta=posture_delta,
        summary=summary,
    )

    logger.info(
        "GraphDiff for %s: +%d -%d nodes, %d new chains, posture %.1f→%.1f (delta %.1f)",
        commit_sha[:8], len(new_nodes), len(removed_nodes), len(new_chains),
        prev_posture_score, new_score, posture_delta,
    )
    return diff


def _fetch_nodes_by_uids(uids: set[str]) -> list[dict]:
    if not uids:
        return []
    results = run_query(
        "MATCH (n) WHERE n.uid IN $uids RETURN n",
        {"uids": list(uids)},
    )
    return [dict(r.get("n", {})) for r in results]


def _find_changed_nodes(common_uids: set[str], commit_sha: str) -> list[dict]:
    """
    Find nodes in the common set whose properties changed.
    Heuristic: Finding nodes with contextual_severity different from raw_severity.
    """
    if not common_uids:
        return []
    results = run_query(
        """
        MATCH (f:Finding)
        WHERE f.uid IN $uids
          AND f.contextual_severity <> f.raw_severity
        RETURN f.uid AS uid, f.raw_severity AS raw, f.contextual_severity AS contextual
        """,
        {"uids": list(common_uids)},
    )
    return [dict(r) for r in results]


def _diff_chains(pre_uids: set[str], post_uids: set[str]) -> tuple[list[dict], list[dict]]:
    """
    Identify new CHAINS_TO edges (in post but not pre) and broken ones (in pre but not post).
    Simplified: query all current chains and return those involving new nodes.
    """
    # New chains: CHAINS_TO edges where either endpoint is in new_node_uids
    new_node_uids = post_uids - pre_uids
    removed_node_uids = pre_uids - post_uids

    new_chains = []
    if new_node_uids:
        results = run_query(
            """
            MATCH (f1:Finding)-[r:CHAINS_TO]->(f2:Finding)
            WHERE f1.uid IN $uids OR f2.uid IN $uids
            RETURN f1.uid AS from_uid, f2.uid AS to_uid,
                   r.evidence AS evidence, r.confidence AS confidence
            """,
            {"uids": list(new_node_uids)},
        )
        new_chains = [dict(r) for r in results]

    broken_chains = []
    if removed_node_uids:
        # Chains involving removed nodes are implicitly broken
        broken_chains = [{"uid": uid, "reason": "node_removed"} for uid in removed_node_uids]

    return new_chains, broken_chains


def _build_summary(
    new_nodes: list[dict],
    removed_nodes: list[dict],
    new_chains: list[dict],
    posture_delta: float,
    new_score: float,
) -> str:
    parts = []

    if new_nodes:
        findings = [n for n in new_nodes if n.get("type") in ("sast", "dependency", "config", "chain")]
        if findings:
            parts.append(f"{len(findings)} new finding(s)")

    if removed_nodes:
        parts.append(f"{len(removed_nodes)} node(s) removed")

    if new_chains:
        parts.append(f"{len(new_chains)} new vulnerability chain(s)")

    if posture_delta > 0:
        direction = f"DEGRADED by {posture_delta:.1f} points"
    elif posture_delta < 0:
        direction = f"IMPROVED by {abs(posture_delta):.1f} points"
    else:
        direction = "NEUTRAL"

    summary = f"Posture {direction} (score: {new_score:.1f}/100)."
    if parts:
        summary += " " + ", ".join(parts).capitalize() + "."

    return summary
