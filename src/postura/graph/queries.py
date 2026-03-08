"""Reusable Cypher query functions for the POSTURA threat graph."""
from postura.graph.connection import run_query


def get_public_endpoints() -> list[dict]:
    """Return all public (unauthenticated) endpoints."""
    return run_query(
        "MATCH (e:Endpoint {is_public: true}) RETURN e"
    )


def get_all_findings(status: str = "open") -> list[dict]:
    """Return all findings with the given status."""
    return run_query(
        "MATCH (f:Finding {status: $status}) RETURN f ORDER BY f.contextual_severity",
        {"status": status},
    )


def get_findings_by_severity(severity: str) -> list[dict]:
    """Return all findings with the given contextual severity."""
    return run_query(
        "MATCH (f:Finding) WHERE f.contextual_severity = $severity RETURN f",
        {"severity": severity},
    )


def get_chains() -> list[dict]:
    """Return all vulnerability chains (CHAINS_TO edges)."""
    return run_query(
        """
        MATCH path = (f1:Finding)-[:CHAINS_TO*1..5]->(f2:Finding)
        RETURN f1, f2, length(path) AS chain_length,
               [n IN nodes(path) | n.uid] AS chain_uids
        ORDER BY chain_length DESC
        """
    )


def get_public_endpoints_reaching_pii() -> list[dict]:
    """Find public endpoints that can reach PII data stores via call graph."""
    return run_query(
        """
        MATCH (e:Endpoint {is_public: true})-[:HANDLED_BY]->(f:Function)
        MATCH path = (f)-[:CALLS*0..5]->(g:Function)-[:READS_FROM|WRITES_TO]->(d:DataStore {contains_pii: true})
        RETURN e.path AS endpoint_path, e.method AS method,
               [n IN nodes(path) | n.name] AS call_chain,
               d.name AS datastore, d.type AS datastore_type
        """
    )


def get_finding_context(finding_uid: str) -> dict:
    """Get the full graph context of a finding: trust zone, reachability, PII."""
    results = run_query(
        """
        MATCH (f:Finding {uid: $uid})
        OPTIONAL MATCH (f)-[:AFFECTS]->(target)
        OPTIONAL MATCH (ep:Endpoint)-[:HANDLED_BY*0..1]->(target)
        OPTIONAL MATCH (ep)-[:IN_ZONE]->(tz:TrustZone)
        OPTIONAL MATCH (target)-[:READS_FROM|WRITES_TO]->(ds:DataStore)
        RETURN f, target, ep, tz, collect(DISTINCT ds) AS datastores
        """,
        {"uid": finding_uid},
    )
    return results[0] if results else {}


def check_reachability_from_public(finding_uid: str) -> bool:
    """Check if a finding is reachable from any public endpoint via CALLS."""
    results = run_query(
        """
        MATCH (finding:Finding {uid: $uid})-[:AFFECTS]->(target:Function)
        MATCH (ep:Endpoint {is_public: true})-[:HANDLED_BY]->(handler:Function)
        MATCH path = (handler)-[:CALLS*0..6]->(target)
        RETURN count(path) > 0 AS reachable
        LIMIT 1
        """,
        {"uid": finding_uid},
    )
    if results:
        return bool(results[0].get("reachable", False))
    return False


def get_posture_score() -> float:
    """
    Compute aggregate posture score.
    Score = 100 - (weighted finding sum / normalization factor), min 0.
    Weights: CRITICAL=10, HIGH=5, MEDIUM=2, LOW=1, INFO=0
    """
    results = run_query(
        """
        MATCH (f:Finding {status: 'open'})
        WITH sum(
            CASE f.contextual_severity
                WHEN 'CRITICAL' THEN 10
                WHEN 'HIGH' THEN 5
                WHEN 'MEDIUM' THEN 2
                WHEN 'LOW' THEN 1
                ELSE 0
            END
        ) AS risk_score
        RETURN risk_score
        """
    )
    if not results:
        return 100.0
    risk = results[0].get("risk_score", 0) or 0
    # Normalize: 0 risk → 100, risk ≥ 100 → 0
    return max(0.0, 100.0 - float(risk))


def get_dependency_blast_radius(dep_name: str) -> dict:
    """Compute blast radius of a compromised dependency."""
    results = run_query(
        """
        MATCH (d:Dependency {name: $dep_name})
        MATCH path = (d)<-[:USES]-(f:Function)<-[:CALLS*0..4]-(g:Function)<-[:HANDLED_BY]-(e:Endpoint)
        RETURN d.name AS dep, count(DISTINCT e) AS exposed_endpoints,
               collect(DISTINCT e.path) AS endpoint_paths,
               any(node IN nodes(path) WHERE node:DataStore AND node.contains_pii) AS reaches_pii
        """,
        {"dep_name": dep_name},
    )
    return results[0] if results else {}


def set_finding_reachability(finding_uid: str, reachable: bool) -> None:
    """Update reachable_from_public property on a Finding node."""
    from postura.graph.connection import run_write
    run_write(
        "MATCH (f:Finding {uid: $uid}) SET f.reachable_from_public = $reachable",
        {"uid": finding_uid, "reachable": reachable},
    )


def get_all_open_finding_uids() -> list[str]:
    results = run_query("MATCH (f:Finding {status: 'open'}) RETURN f.uid AS uid")
    return [r["uid"] for r in results]
