"""Tests for reasoning/tools.py against a live Neo4j graph.

Requires Neo4j running with the Flask fixture graph loaded.
Skip automatically if Neo4j is not available (same pattern as test_e2e_phase2.py).
"""
from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _neo4j_available() -> bool:
    try:
        from postura.graph.connection import health_check
        return health_check()
    except Exception:
        return False


neo4j = pytest.mark.skipif(
    not _neo4j_available(),
    reason="Neo4j not available",
)


@pytest.fixture(scope="session")
def flask_graph():
    """Build the Flask fixture graph once for the whole session."""
    if not _neo4j_available():
        pytest.skip("Neo4j not available")

    from pathlib import Path
    from postura.ingest.ast_parser import parse_directory
    from postura.ingest.sast_runner import run_sast
    from postura.ingest.endpoint_extractor import extract_endpoints
    from postura.ingest.config_analyzer import analyze_directory
    from postura.models.ingest import StructuredIngestResult
    from postura.graph.builder import GraphBuilder
    from postura.graph.schema import init_schema

    fixture = str(Path(__file__).parent.parent / "fixtures" / "vulnerable_flask_app")
    init_schema()

    nodes, edges, accesses = parse_directory(fixture)
    findings = run_sast(fixture)
    endpoints = extract_endpoints(fixture)
    config_issues = analyze_directory(fixture)

    result = StructuredIngestResult(
        ast_nodes=nodes,
        call_edges=edges,
        endpoints=endpoints,
        sast_findings=findings,
        dep_vulnerabilities=[],
        config_issues=config_issues,
        data_accesses=accesses,
        file_imports={},
    )
    GraphBuilder(result).build()
    return result


# ---------------------------------------------------------------------------
# graph_query
# ---------------------------------------------------------------------------

@neo4j
def test_graph_query_returns_rows(flask_graph):
    from postura.reasoning.tools import graph_query
    rows = graph_query("MATCH (f:Finding) RETURN count(f) AS c")
    assert isinstance(rows, list)
    assert len(rows) > 0
    assert "c" in rows[0]
    assert rows[0]["c"] > 0


@neo4j
def test_graph_query_blocks_writes(flask_graph):
    from postura.reasoning.tools import graph_query
    with pytest.raises(ValueError, match="read operations"):
        graph_query("CREATE (n:Foo) RETURN n")


@neo4j
def test_graph_query_returns_functions(flask_graph):
    from postura.reasoning.tools import graph_query
    rows = graph_query("MATCH (fn:Function) RETURN fn.qualified_name AS name LIMIT 5")
    assert len(rows) > 0
    assert "name" in rows[0]


# ---------------------------------------------------------------------------
# trace_dataflow
# ---------------------------------------------------------------------------

@neo4j
def test_trace_dataflow_from_endpoint(flask_graph):
    from postura.reasoning.tools import graph_query, trace_dataflow
    endpoints = graph_query("MATCH (ep:Endpoint) RETURN ep.uid AS uid LIMIT 1")
    if not endpoints:
        pytest.skip("No endpoints in graph")
    uid = endpoints[0]["uid"]
    paths = trace_dataflow(uid, "DataStore")
    assert isinstance(paths, list)


@neo4j
def test_trace_dataflow_unknown_uid(flask_graph):
    from postura.reasoning.tools import trace_dataflow
    paths = trace_dataflow("nonexistent:uid:xyz", "DataStore")
    assert paths == []


# ---------------------------------------------------------------------------
# find_chains
# ---------------------------------------------------------------------------

@neo4j
def test_find_chains_all(flask_graph):
    from postura.reasoning.tools import find_chains
    chains = find_chains(None)
    assert isinstance(chains, list)


@neo4j
def test_find_chains_specific_finding(flask_graph):
    from postura.reasoning.tools import graph_query, find_chains
    findings = graph_query("MATCH (f:Finding) RETURN f.uid AS uid LIMIT 1")
    if not findings:
        pytest.skip("No findings in graph")
    uid = findings[0]["uid"]
    chains = find_chains(uid)
    assert isinstance(chains, list)


# ---------------------------------------------------------------------------
# assess_exploitability
# ---------------------------------------------------------------------------

@neo4j
def test_assess_exploitability_returns_context(flask_graph):
    from postura.reasoning.tools import graph_query, assess_exploitability
    findings = graph_query("MATCH (f:Finding) RETURN f.uid AS uid LIMIT 1")
    if not findings:
        pytest.skip("No findings in graph")
    uid = findings[0]["uid"]
    ctx = assess_exploitability(uid)
    assert isinstance(ctx, dict)
    assert "error" not in ctx
    assert "is_publicly_reachable" in ctx
    assert "exposes_pii" in ctx
    assert "in_chain" in ctx
    assert "trust_zones" in ctx


@neo4j
def test_assess_exploitability_unknown_uid(flask_graph):
    from postura.reasoning.tools import assess_exploitability
    ctx = assess_exploitability("nonexistent:uid:xyz")
    assert "error" in ctx
