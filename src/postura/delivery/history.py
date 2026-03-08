"""Posture history — P5.3

Stores PostureSnapshot records in Neo4j (as :PostureSnapshot nodes) and
provides retrieval for trend analysis.

A snapshot is taken after every successful analysis run, providing a
time-series of security posture across commits.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from postura.graph.connection import run_query, run_write
from postura.models.findings import PostureSnapshot

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Write
# ---------------------------------------------------------------------------

def record_snapshot(
    commit_sha: str,
    score: float,
    finding_counts: dict[str, int],
    chain_count: int = 0,
    repo: str = "",
    pr_number: int | None = None,
    posture_change: str = "NEUTRAL",
) -> PostureSnapshot:
    """
    Persist a PostureSnapshot to Neo4j and return it.

    A PostureSnapshot node stores the full posture state at a given commit SHA.
    """
    now = datetime.now(timezone.utc).isoformat()
    snapshot = PostureSnapshot(
        commit_sha=commit_sha,
        timestamp=now,
        score=score,
        finding_counts=finding_counts,
        chain_count=chain_count,
    )

    run_write(
        """
        MERGE (s:PostureSnapshot {commit_sha: $commit_sha})
        SET s.timestamp = $timestamp,
            s.score = $score,
            s.chain_count = $chain_count,
            s.repo = $repo,
            s.pr_number = $pr_number,
            s.posture_change = $posture_change,
            s.critical_count = $critical_count,
            s.high_count = $high_count,
            s.medium_count = $medium_count,
            s.low_count = $low_count
        """,
        {
            "commit_sha": commit_sha,
            "timestamp": now,
            "score": score,
            "chain_count": chain_count,
            "repo": repo,
            "pr_number": pr_number,
            "posture_change": posture_change,
            "critical_count": finding_counts.get("CRITICAL", 0),
            "high_count": finding_counts.get("HIGH", 0),
            "medium_count": finding_counts.get("MEDIUM", 0),
            "low_count": finding_counts.get("LOW", 0),
        },
    )
    logger.info("Recorded posture snapshot for %s: score=%.1f", commit_sha[:8], score)
    return snapshot


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------

def get_posture_history(limit: int = 50, repo: str = "") -> list[dict]:
    """
    Return posture snapshots ordered most-recent first.

    Args:
        limit: Maximum number of snapshots to return.
        repo: Filter by repo name (empty = all repos).
    """
    if repo:
        rows = run_query(
            """
            MATCH (s:PostureSnapshot {repo: $repo})
            RETURN s.commit_sha AS commit_sha, s.timestamp AS timestamp,
                   s.score AS score, s.chain_count AS chain_count,
                   s.posture_change AS posture_change,
                   s.critical_count AS critical_count, s.high_count AS high_count,
                   s.medium_count AS medium_count, s.low_count AS low_count,
                   s.repo AS repo, s.pr_number AS pr_number
            ORDER BY s.timestamp DESC
            LIMIT $limit
            """,
            {"repo": repo, "limit": limit},
        )
    else:
        rows = run_query(
            """
            MATCH (s:PostureSnapshot)
            RETURN s.commit_sha AS commit_sha, s.timestamp AS timestamp,
                   s.score AS score, s.chain_count AS chain_count,
                   s.posture_change AS posture_change,
                   s.critical_count AS critical_count, s.high_count AS high_count,
                   s.medium_count AS medium_count, s.low_count AS low_count,
                   s.repo AS repo, s.pr_number AS pr_number
            ORDER BY s.timestamp DESC
            LIMIT $limit
            """,
            {"limit": limit},
        )
    return [dict(r) for r in rows]


def get_posture_trend(window: int = 10, repo: str = "") -> dict:
    """
    Compute trend metrics over the last `window` snapshots.

    Returns:
        {
          current_score, previous_score, delta,
          trend: "improving" | "degrading" | "stable",
          snapshots: [...]
        }
    """
    snapshots = get_posture_history(limit=window, repo=repo)
    if not snapshots:
        return {"trend": "unknown", "snapshots": []}

    current = snapshots[0]["score"] or 0.0
    previous = snapshots[-1]["score"] or current if len(snapshots) > 1 else current
    delta = round(current - previous, 1)

    if delta > 2:
        trend = "improving"
    elif delta < -2:
        trend = "degrading"
    else:
        trend = "stable"

    return {
        "current_score": round(current, 1),
        "previous_score": round(previous, 1),
        "delta": delta,
        "trend": trend,
        "snapshots": snapshots,
    }


def get_top_risk_findings(limit: int = 10) -> list[dict]:
    """Return the highest-risk open findings with graph context."""
    rows = run_query(
        """
        MATCH (f:Finding {status: 'open'})
        OPTIONAL MATCH (f)-[:AFFECTS]->(fn:Function)
        OPTIONAL MATCH (ep:Endpoint)-[:HANDLED_BY]->(fn)
        RETURN f.uid AS uid, f.title AS title, f.cwe_id AS cwe_id,
               f.contextual_severity AS severity, f.file AS file, f.line AS line,
               f.reachable_from_public AS reachable,
               collect(DISTINCT ep.path) AS endpoints
        ORDER BY
            CASE f.contextual_severity
                WHEN 'CRITICAL' THEN 0
                WHEN 'HIGH' THEN 1
                WHEN 'MEDIUM' THEN 2
                WHEN 'LOW' THEN 3
                ELSE 4
            END, f.reachable_from_public DESC
        LIMIT $limit
        """,
        {"limit": limit},
    )
    return [dict(r) for r in rows]
