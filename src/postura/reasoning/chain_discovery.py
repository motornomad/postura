"""Rule-based vulnerability chain discovery.

Creates :CHAINS_TO edges between Finding nodes when compositional risk exists.

Rules implemented:
  Rule 1 — PII Exposure via Public Endpoint + SQLi
    Public endpoint → handler → CALLS* → function with SQLi finding
    → READS_FROM/WRITES_TO → DataStore with PII = CHAIN

  Rule 2 — Missing Auth on Endpoint accessing sensitive data
    Public endpoint (no auth) → handler → CALLS* → function reading PII datastore = CHAIN

  Rule 3 — Supply Chain: Vulnerable dep used by function reachable from public endpoint
    Dependency with CVE finding → used by function → reachable from public endpoint = CHAIN

Each discovered chain creates a :CHAINS_TO edge between the constituent Findings
with an evidence string and confidence score.
"""
from __future__ import annotations

import logging
from postura.graph.connection import run_query, run_write

logger = logging.getLogger(__name__)


def discover_chains() -> int:
    """
    Run all chain discovery rules and create CHAINS_TO edges.
    Returns the number of new chains created.
    """
    total = 0
    total += _rule1_public_sqli_pii()
    total += _rule2_missing_auth_pii()
    total += _rule3_supply_chain_public()
    logger.info("Chain discovery: %d chains created/updated", total)
    return total


# ---------------------------------------------------------------------------
# Rule 1: Public endpoint → SQLi finding → PII DataStore
# ---------------------------------------------------------------------------

def _rule1_public_sqli_pii() -> int:
    """
    Detect: unauthenticated endpoint whose call chain reaches a SQLi finding
    that reads from a PII DataStore.
    """
    results = run_query(
        """
        // Find SQLi findings that affect functions reading from PII datastores
        MATCH (sqli:Finding)
        WHERE sqli.cwe_id IN ['CWE-89', 'CWE-564'] OR sqli.rule_id CONTAINS 'sql'
              OR sqli.title CONTAINS 'SQL' OR sqli.description CONTAINS 'SQL inject'
        MATCH (sqli)-[:AFFECTS]->(vuln_fn:Function)
        MATCH (vuln_fn)-[:READS_FROM|WRITES_TO]->(ds:DataStore {contains_pii: true})

        // Find public endpoints whose handlers can reach the vulnerable function
        MATCH (ep:Endpoint {is_public: true})-[:HANDLED_BY]->(handler:Function)
        MATCH path = (handler)-[:CALLS*0..6]->(vuln_fn)

        // Is there a missing-auth finding for this endpoint or something nearby?
        OPTIONAL MATCH (auth_finding:Finding)-[:AFFECTS]->(ep)

        RETURN DISTINCT sqli.uid AS sqli_uid, sqli.title AS sqli_title,
               ep.path AS ep_path, ep.uid AS ep_uid,
               ds.name AS ds_name, ds.uid AS ds_uid,
               auth_finding.uid AS auth_uid,
               length(path) AS path_len
        """
    )

    count = 0
    for row in results:
        sqli_uid = row.get("sqli_uid")
        auth_uid = row.get("auth_uid")

        if not sqli_uid:
            continue

        # If there's also a missing-auth finding, chain them
        if auth_uid:
            evidence = (
                f"Public endpoint '{row.get('ep_path')}' (missing auth) leads via call graph "
                f"to SQL injection in a function that reads from PII datastore '{row.get('ds_name')}'. "
                f"Call chain depth: {row.get('path_len', '?')} hops."
            )
            _create_chain_edge(auth_uid, sqli_uid, evidence, confidence=0.95, path_length=2)
            count += 1
        else:
            # Still create a chain from the endpoint's own "public access" context
            # represented as a note on the SQLi finding itself
            _annotate_reachable(sqli_uid, reachable=True, from_public=True)

    return count


# ---------------------------------------------------------------------------
# Rule 2: Missing auth on endpoint + PII data access
# ---------------------------------------------------------------------------

def _rule2_missing_auth_pii() -> int:
    """
    Detect: endpoint with missing-auth finding whose call chain reads PII.
    """
    results = run_query(
        """
        // Missing auth findings on endpoints
        MATCH (missing_auth:Finding)-[:AFFECTS]->(ep:Endpoint)
        WHERE (missing_auth.type = 'sast' OR missing_auth.rule_id CONTAINS 'auth'
              OR missing_auth.description CONTAINS 'auth')

        // The endpoint is public
        AND ep.is_public = true

        // Handler can reach a PII datastore
        MATCH (ep)-[:HANDLED_BY]->(handler:Function)
        MATCH path = (handler)-[:CALLS*0..5]->(fn:Function)-[:READS_FROM|WRITES_TO]->(ds:DataStore {contains_pii: true})

        // Any finding on the function reaching PII
        OPTIONAL MATCH (pii_finding:Finding)-[:AFFECTS]->(fn)

        RETURN DISTINCT missing_auth.uid AS auth_uid,
               pii_finding.uid AS pii_uid,
               ep.path AS ep_path,
               ds.name AS ds_name,
               length(path) AS path_len
        """
    )

    count = 0
    for row in results:
        auth_uid = row.get("auth_uid")
        pii_uid = row.get("pii_uid")

        if auth_uid and pii_uid and auth_uid != pii_uid:
            evidence = (
                f"Endpoint '{row.get('ep_path')}' has no authentication and its call chain "
                f"reaches a function with a finding that accesses PII datastore '{row.get('ds_name')}'. "
                f"An attacker can directly access user data without authentication."
            )
            _create_chain_edge(auth_uid, pii_uid, evidence, confidence=0.90, path_length=2)
            count += 1

    return count


# ---------------------------------------------------------------------------
# Rule 3: Vulnerable dependency reachable from public endpoint
# ---------------------------------------------------------------------------

def _rule3_supply_chain_public() -> int:
    """
    Detect: CVE finding on a dependency used by a function reachable from a public endpoint.
    """
    results = run_query(
        """
        // CVE findings on dependencies
        MATCH (cve:Finding {type: 'dependency'})-[:AFFECTS]->(dep:Dependency)

        // Functions that use this dependency (via import)
        MATCH (fn:Function)-[:USES]->(dep)

        // Public endpoint can reach this function
        MATCH (ep:Endpoint {is_public: true})-[:HANDLED_BY]->(handler:Function)
        MATCH path = (handler)-[:CALLS*0..5]->(fn)

        RETURN DISTINCT cve.uid AS cve_uid, cve.title AS cve_title,
               dep.name AS dep_name,
               ep.path AS ep_path,
               fn.qualified_name AS fn_name,
               length(path) AS path_len
        """
    )

    count = 0
    for row in results:
        cve_uid = row.get("cve_uid")
        if not cve_uid:
            continue

        # Annotate the CVE finding as reachable from public
        _annotate_reachable(cve_uid, reachable=True, from_public=True)
        count += 1

    return count


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_chain_edge(
    from_uid: str,
    to_uid: str,
    evidence: str,
    confidence: float = 0.8,
    path_length: int = 2,
) -> None:
    """Create a :CHAINS_TO edge between two Finding nodes."""
    run_write(
        """
        MATCH (f1:Finding {uid: $from_uid})
        MATCH (f2:Finding {uid: $to_uid})
        MERGE (f1)-[r:CHAINS_TO]->(f2)
        SET r.evidence = $evidence, r.confidence = $confidence, r.path_length = $path_length
        """,
        {
            "from_uid": from_uid,
            "to_uid": to_uid,
            "evidence": evidence,
            "confidence": confidence,
            "path_length": path_length,
        },
    )


def _annotate_reachable(finding_uid: str, reachable: bool, from_public: bool) -> None:
    """Set reachability properties on a Finding node."""
    run_write(
        """
        MATCH (f:Finding {uid: $uid})
        SET f.reachable_from_public = $reachable
        """,
        {"uid": finding_uid, "reachable": reachable},
    )


def get_chains_for_finding(finding_uid: str) -> list[dict]:
    """Return all chains involving a specific finding."""
    return run_query(
        """
        MATCH chain = (f1:Finding {uid: $uid})-[:CHAINS_TO*1..5]->(f2:Finding)
        RETURN [n IN nodes(chain) | {uid: n.uid, title: n.title, severity: n.contextual_severity}] AS links,
               length(chain) AS chain_length,
               relationships(chain)[0].evidence AS evidence
        UNION
        MATCH chain = (f1:Finding)-[:CHAINS_TO*1..5]->(f2:Finding {uid: $uid})
        RETURN [n IN nodes(chain) | {uid: n.uid, title: n.title, severity: n.contextual_severity}] AS links,
               length(chain) AS chain_length,
               relationships(chain)[0].evidence AS evidence
        """,
        {"uid": finding_uid},
    )
