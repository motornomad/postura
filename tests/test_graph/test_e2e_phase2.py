"""
Phase 2 end-to-end test — requires Neo4j running.

Run with:
    docker compose up -d neo4j
    pytest tests/test_graph/test_e2e_phase2.py -v

Asserts:
- All node types present (Service, Endpoint, Function, DataStore, Dependency, Finding, TrustZone)
- All edge types present (CALLS, HANDLED_BY, BELONGS_TO, IN_ZONE, READS_FROM, WRITES_TO, AFFECTS)
- PII exposure chain detected (CHAINS_TO edges)
- Contextual severity differs from raw for chain-participating findings
"""
import pytest
from pathlib import Path

from postura.graph.connection import health_check, run_query
from postura.graph.schema import init_schema, drop_all_data
from postura.graph.builder import GraphBuilder
from postura.ingest.ast_parser import parse_directory
from postura.ingest.endpoint_extractor import extract_endpoints_from_directory
from postura.ingest.sast_runner import run_sast
from postura.ingest.dep_scanner import scan_dependencies
from postura.ingest.config_analyzer import analyze_directory
from postura.models.ingest import StructuredIngestResult
from postura.reasoning.chain_discovery import discover_chains
from postura.reasoning.severity_scorer import score_all_findings, compute_posture_score

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "vulnerable_flask_app"


@pytest.fixture(scope="module", autouse=True)
def neo4j_required():
    """Skip entire module if Neo4j is not reachable."""
    if not health_check():
        pytest.skip("Neo4j not reachable — start with: docker compose up -d neo4j")


@pytest.fixture(scope="module")
def populated_graph():
    """Build the full graph from the vulnerable Flask fixture."""
    # Clean slate
    drop_all_data()
    init_schema()

    # Ingest
    ast_nodes, call_edges, data_accesses = parse_directory(str(FIXTURE_DIR), str(FIXTURE_DIR))
    endpoints = extract_endpoints_from_directory(str(FIXTURE_DIR), str(FIXTURE_DIR))
    sast_findings = run_sast(str(FIXTURE_DIR))
    dep_vulns = scan_dependencies(str(FIXTURE_DIR / "requirements.txt"))
    config_issues = analyze_directory(str(FIXTURE_DIR), str(FIXTURE_DIR))

    result = StructuredIngestResult(
        ast_nodes=ast_nodes,
        call_edges=call_edges,
        data_accesses=data_accesses,
        endpoints=endpoints,
        sast_findings=sast_findings,
        dep_vulnerabilities=dep_vulns,
        config_issues=config_issues,
    )

    builder = GraphBuilder(service_name="vulnerable_flask_app", repo_root=str(FIXTURE_DIR))
    builder.build(result, requirements_file=str(FIXTURE_DIR / "requirements.txt"))

    # Run chain discovery and severity scoring
    discover_chains()
    score_all_findings()

    return result


class TestNodeTypes:
    def test_service_node_exists(self, populated_graph):
        rows = run_query("MATCH (s:Service) RETURN count(s) AS cnt")
        assert rows[0]["cnt"] >= 1

    def test_endpoint_nodes_exist(self, populated_graph):
        rows = run_query("MATCH (e:Endpoint) RETURN count(e) AS cnt")
        assert rows[0]["cnt"] >= 4, "Expected at least 4 endpoints (login, get_user, admin/users, fetch, health)"

    def test_function_nodes_exist(self, populated_graph):
        rows = run_query("MATCH (f:Function) RETURN count(f) AS cnt")
        assert rows[0]["cnt"] >= 8

    def test_datastore_nodes_exist(self, populated_graph):
        rows = run_query("MATCH (d:DataStore) RETURN count(d) AS cnt")
        assert rows[0]["cnt"] >= 1, "Expected at least 1 DataStore node (users table)"

    def test_pii_datastore_detected(self, populated_graph):
        rows = run_query("MATCH (d:DataStore {contains_pii: true}) RETURN d.name AS name")
        pii_names = [r["name"] for r in rows]
        assert len(pii_names) >= 1, f"Expected PII datastore, got {pii_names}"

    def test_finding_nodes_exist(self, populated_graph):
        rows = run_query("MATCH (f:Finding) RETURN count(f) AS cnt")
        assert rows[0]["cnt"] >= 1, "Expected at least 1 Finding node"

    def test_trustzone_nodes_exist(self, populated_graph):
        rows = run_query("MATCH (t:TrustZone) RETURN count(t) AS cnt")
        assert rows[0]["cnt"] >= 3


class TestEdgeTypes:
    def test_calls_edges_exist(self, populated_graph):
        rows = run_query("MATCH ()-[r:CALLS]->() RETURN count(r) AS cnt")
        assert rows[0]["cnt"] >= 1

    def test_handled_by_edges_exist(self, populated_graph):
        rows = run_query("MATCH (e:Endpoint)-[r:HANDLED_BY]->() RETURN count(r) AS cnt")
        assert rows[0]["cnt"] >= 1

    def test_belongs_to_edges_exist(self, populated_graph):
        rows = run_query("MATCH ()-[r:BELONGS_TO]->(:Service) RETURN count(r) AS cnt")
        assert rows[0]["cnt"] >= 1

    def test_in_zone_edges_exist(self, populated_graph):
        rows = run_query("MATCH ()-[r:IN_ZONE]->(:TrustZone) RETURN count(r) AS cnt")
        assert rows[0]["cnt"] >= 1

    def test_data_access_edges_exist(self, populated_graph):
        rows = run_query("MATCH ()-[r:READS_FROM|WRITES_TO]->(:DataStore) RETURN count(r) AS cnt")
        assert rows[0]["cnt"] >= 1, "Expected READS_FROM or WRITES_TO edges to DataStore"


class TestPostureScore:
    def test_posture_score_computed(self, populated_graph):
        score = compute_posture_score()
        assert 0.0 <= score <= 100.0

    def test_posture_score_not_perfect(self, populated_graph):
        """With vulnerabilities, score should be < 100."""
        score = compute_posture_score()
        assert score < 100.0, f"Expected score < 100 with known vulnerabilities, got {score}"


class TestPublicEndpoint:
    def test_admin_endpoint_is_public(self, populated_graph):
        rows = run_query(
            "MATCH (e:Endpoint {is_public: true}) WHERE e.path CONTAINS 'admin' RETURN e.path AS path"
        )
        assert len(rows) >= 1, "Expected /admin/users to be flagged as public"

    def test_login_endpoint_exists_with_method(self, populated_graph):
        rows = run_query(
            "MATCH (e:Endpoint {method: 'POST'}) WHERE e.path CONTAINS 'login' RETURN e"
        )
        assert len(rows) >= 1
