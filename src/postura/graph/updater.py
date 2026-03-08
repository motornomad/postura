"""Incremental graph updater — P3.4a + P3.4b

Implements the soft-delete → rebuild → diff algorithm:
  1. Identify affected subgraph (nodes whose file is in changed_files)
  2. Mark affected nodes as stale
  3. Re-ingest changed files only
  4. Merge fresh data into graph (MERGE creates/updates)
  5. Remove nodes still marked stale (deleted in code)
  6. Return the affected subgraph node/edge UIDs for diffing
"""
from __future__ import annotations

import logging
from pathlib import Path

from postura.graph.connection import run_query, run_write
from postura.graph.builder import GraphBuilder
from postura.ingest.ast_parser import parse_file
from postura.ingest.endpoint_extractor import extract_endpoints
from postura.ingest.sast_runner import run_sast
from postura.ingest.config_analyzer import analyze_file
from postura.models.ingest import StructuredIngestResult

logger = logging.getLogger(__name__)


def update_graph_for_files(
    changed_files: list[str],
    repo_path: str,
    service_name: str = "app",
    requirements_file: str = "",
) -> dict:
    """
    Incrementally update the graph for the given changed files.

    Returns a snapshot dict with pre/post UIDs for diffing.
    """
    if not changed_files:
        return {"pre_uids": set(), "post_uids": set(), "changed_files": []}

    # Normalize paths to repo-relative (handles absolute paths from webhooks)
    _repo = Path(repo_path)
    normalized: list[str] = []
    for f in changed_files:
        p = Path(f)
        try:
            normalized.append(str(p.relative_to(_repo)))
        except ValueError:
            normalized.append(f)  # already relative
    changed_files = normalized

    # Step 1: Identify affected subgraph UIDs (before update)
    pre_snapshot = _snapshot_affected_subgraph(changed_files)

    # Step 2: Mark affected nodes stale
    _mark_stale(changed_files)

    # Step 3: Re-ingest changed files
    result = _ingest_changed_files(changed_files, repo_path)

    # Step 4: Rebuild affected subgraph
    builder = GraphBuilder(service_name=service_name, repo_root=repo_path)
    builder.build(result, requirements_file=requirements_file)

    # Step 5: Remove still-stale nodes (code was deleted)
    removed = _remove_stale_nodes(changed_files)
    logger.info("Removed %d stale nodes after rebuild", removed)

    # Step 6: Snapshot post-update state
    post_snapshot = _snapshot_affected_subgraph(changed_files)

    return {
        "pre_uids": pre_snapshot,
        "post_uids": post_snapshot,
        "changed_files": changed_files,
        "removed_count": removed,
    }


# ---------------------------------------------------------------------------
# Subgraph snapshot
# ---------------------------------------------------------------------------

def _snapshot_affected_subgraph(changed_files: list[str]) -> set[str]:
    """
    Return UIDs of all nodes whose file is in changed_files,
    plus 1-hop neighbors.
    """
    results = run_query(
        """
        MATCH (n)
        WHERE n.file IN $files AND n.file IS NOT NULL
        OPTIONAL MATCH (n)-[r]-(m)
        WITH collect(DISTINCT n.uid) + collect(DISTINCT m.uid) AS uids
        RETURN [uid IN uids WHERE uid IS NOT NULL] AS uids
        """,
        {"files": changed_files},
    )
    if not results:
        return set()
    return set(results[0].get("uids", []))


# ---------------------------------------------------------------------------
# Stale marking
# ---------------------------------------------------------------------------

def _mark_stale(changed_files: list[str]) -> int:
    """Mark all nodes in changed_files as stale. Returns count."""
    result = run_query(
        """
        MATCH (n)
        WHERE n.file IN $files AND n.file IS NOT NULL
        SET n._stale = true
        RETURN count(n) AS cnt
        """,
        {"files": changed_files},
    )
    cnt = result[0]["cnt"] if result else 0
    logger.info("Marked %d nodes as stale for files: %s", cnt, changed_files)
    return cnt


def _remove_stale_nodes(changed_files: list[str]) -> int:
    """Remove nodes that are still stale after rebuild (they no longer exist in code)."""
    result = run_query(
        """
        MATCH (n)
        WHERE n._stale = true AND n.file IN $files
        DETACH DELETE n
        RETURN count(n) AS cnt
        """,
        {"files": changed_files},
    )
    return result[0]["cnt"] if result else 0


# ---------------------------------------------------------------------------
# Partial ingest
# ---------------------------------------------------------------------------

def _ingest_changed_files(changed_files: list[str], repo_path: str) -> StructuredIngestResult:
    """Re-run ingest pipeline on changed files only."""
    from postura.ingest.dep_scanner import scan_dependencies

    result = StructuredIngestResult()

    for rel_file in changed_files:
        abs_path = str(Path(repo_path) / rel_file)
        if not Path(abs_path).exists():
            continue  # file was deleted

        if rel_file.endswith(".py"):
            module = rel_file.replace("/", ".").replace("\\", ".")[:-3]

            # AST parse
            nodes, edges, accesses, imports = parse_file(abs_path, repo_path)
            result.ast_nodes.extend(nodes)
            result.call_edges.extend(edges)
            result.data_accesses.extend(accesses)
            if imports:
                result.file_imports[rel_file] = imports

            # Endpoint extraction
            eps = extract_endpoints(abs_path, module, repo_path)
            result.endpoints.extend(eps)

            # Config issues for this file
            issues = analyze_file(abs_path, repo_path)
            result.config_issues.extend(issues)

    # SAST scan on all changed Python files (run as a batch for efficiency)
    py_files = [f for f in changed_files if f.endswith(".py")]
    if py_files:
        # Run SAST on whole repo path — findings are filtered by file
        all_findings = run_sast(repo_path)
        result.sast_findings = [f for f in all_findings if f.file in changed_files]

    return result
