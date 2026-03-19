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
    total += _rule_taint_inter_function()   # V2.1c: 1-hop inter-function taint propagation
    total += _rule1_public_sqli_pii()
    total += _rule2_missing_auth_pii()
    total += _rule3_supply_chain_public()
    logger.info("Chain discovery: %d chains created/updated", total)
    return total


# ---------------------------------------------------------------------------
# V2.1c: Inter-function taint propagation — 1-hop TAINT_FLOWS_TO edges
# ---------------------------------------------------------------------------

def _rule_taint_inter_function() -> int:
    """Create TAINT_FLOWS_TO edges between caller/callee when:
      - Callee has confirmed taint flow (has_taint_flow=true)
      - Caller has confirmed HTTP request sources (taint_sources field populated)
      - Caller CALLS callee

    This captures "login() passes request.form data → get_user_by_name() → cursor.execute".
    """
    results = run_query(
        """
        MATCH (callee:Function {has_taint_flow: true})
        MATCH (caller:Function)-[:CALLS]->(callee)
        WHERE caller.taint_sources IS NOT NULL AND size(caller.taint_sources) > 0
        RETURN DISTINCT caller.uid AS caller_uid, callee.uid AS callee_uid,
               caller.qualified_name AS caller_name, callee.qualified_name AS callee_name,
               callee.taint_sink_types AS sink_types,
               callee.taint_source_params AS sink_params
        """
    )

    count = 0
    for row in results:
        caller_uid = row.get("caller_uid")
        callee_uid = row.get("callee_uid")
        if not caller_uid or not callee_uid or caller_uid == callee_uid:
            continue

        sink_types = row.get("sink_types") or []
        sink_params = row.get("sink_params") or []
        sink_type_str = ", ".join(sink_types) if sink_types else "unknown"
        param_str = ", ".join(sink_params) if sink_params else "unknown"

        run_write(
            """
            MATCH (caller:Function {uid: $caller_uid})
            MATCH (callee:Function {uid: $callee_uid})
            MERGE (caller)-[r:TAINT_FLOWS_TO]->(callee)
            SET r.hop = 1,
                r.sink_type = $sink_type,
                r.via_param = $via_param,
                r.confidence = 0.9
            """,
            {
                "caller_uid": caller_uid,
                "callee_uid": callee_uid,
                "sink_type": sink_type_str,
                "via_param": param_str,
            },
        )
        count += 1

    if count:
        logger.info("Taint inter-function: created %d 1-hop TAINT_FLOWS_TO edges", count)
    return count


# ---------------------------------------------------------------------------
# Rule 1: Public endpoint → SQLi finding → PII DataStore
# ---------------------------------------------------------------------------

def _rule1_public_sqli_pii() -> int:
    """
    Detect: unauthenticated endpoint whose call chain reaches a SQLi finding
    reachable from a public endpoint that also has access to a PII DataStore.
    Creates CHAINS_TO from SQLi Finding → PII DataStore.
    """
    results = run_query(
        """
        // Find SQLi findings on functions
        MATCH (sqli:Finding)
        WHERE sqli.cwe_id IN ['CWE-89', 'CWE-564'] OR sqli.rule_id CONTAINS 'sql'
              OR sqli.title CONTAINS 'SQL' OR sqli.description CONTAINS 'SQL inject'
        MATCH (sqli)-[:AFFECTS]->(vuln_fn:Function)

        // Public endpoint can reach the vulnerable function
        MATCH (ep:Endpoint {is_public: true})-[:HANDLED_BY]->(handler:Function)
        MATCH (handler)-[:CALLS*0..6]->(vuln_fn)

        // PII datastore reachable anywhere from this endpoint's call graph
        MATCH (ep)-[:HANDLED_BY]->(h2:Function)
        MATCH (h2)-[:CALLS*0..6]->(pii_fn:Function)-[:READS_FROM|WRITES_TO]->(ds:DataStore {contains_pii: true})

        // Check for taint evidence: any function in the chain has a confirmed taint flow
        OPTIONAL MATCH (handler)-[:TAINT_FLOWS_TO*0..3]->(tainted_fn:Function {has_taint_flow: true})

        RETURN DISTINCT sqli.uid AS sqli_uid, sqli.title AS sqli_title,
               ep.path AS ep_path,
               ds.name AS ds_name, ds.uid AS ds_uid,
               tainted_fn IS NOT NULL AS has_taint_evidence
        """
    )

    count = 0
    seen: set[tuple[str, str]] = set()
    for row in results:
        sqli_uid = row.get("sqli_uid")
        ds_uid = row.get("ds_uid")
        if not sqli_uid or not ds_uid:
            continue
        key = (sqli_uid, ds_uid)
        if key in seen:
            continue
        seen.add(key)

        has_taint = bool(row.get("has_taint_evidence"))
        taint_note = (
            " Taint analysis confirms user-controlled input flows to the SQL sink."
            if has_taint else ""
        )
        evidence = (
            f"SQL injection in function reachable from public endpoint '{row.get('ep_path')}'. "
            f"The endpoint's call graph also accesses PII datastore '{row.get('ds_name')}'."
            f"{taint_note} An attacker can exploit the injection to exfiltrate user PII."
        )
        confidence = 1.0 if has_taint else 0.90
        _create_chain_to_datastore(sqli_uid, ds_uid, evidence, confidence=confidence)
        _annotate_reachable(sqli_uid, reachable=True, from_public=True)
        count += 1

    return count


# ---------------------------------------------------------------------------
# Rule 2: Missing auth on endpoint + PII data access
# ---------------------------------------------------------------------------

def _rule2_missing_auth_pii() -> int:
    """
    Detect: CWE-306 finding on a handler function whose call chain reads PII.
    Creates CHAINS_TO from CWE-306 Finding → PII DataStore.
    """
    results = run_query(
        """
        // CWE-306 finding on a handler function
        MATCH (missing_auth:Finding {cwe_id: 'CWE-306'})-[:AFFECTS]->(handler:Function)

        // Handler is linked to a public endpoint
        MATCH (ep:Endpoint {is_public: true})-[:HANDLED_BY]->(handler)

        // Call chain reaches a PII datastore
        MATCH (handler)-[:CALLS*0..5]->(fn:Function)-[:READS_FROM|WRITES_TO]->(ds:DataStore {contains_pii: true})

        // Check for taint evidence: handler or its callees have confirmed HTTP request sources
        OPTIONAL MATCH (handler)-[:TAINT_FLOWS_TO*0..3]->(tainted_fn:Function {has_taint_flow: true})

        RETURN DISTINCT missing_auth.uid AS auth_uid,
               ep.path AS ep_path,
               ds.name AS ds_name, ds.uid AS ds_uid,
               tainted_fn IS NOT NULL AS has_taint_evidence
        """
    )

    count = 0
    seen: set[tuple[str, str]] = set()
    for row in results:
        auth_uid = row.get("auth_uid")
        ds_uid = row.get("ds_uid")
        if not auth_uid or not ds_uid:
            continue
        key = (auth_uid, ds_uid)
        if key in seen:
            continue
        seen.add(key)

        has_taint = bool(row.get("has_taint_evidence"))
        taint_note = (
            " Taint analysis confirms user-controlled input flows from the request to the PII datastore."
            if has_taint else ""
        )
        evidence = (
            f"Endpoint '{row.get('ep_path')}' has no authentication (CWE-306) and its "
            f"call chain directly reads PII from datastore '{row.get('ds_name')}'."
            f"{taint_note} "
            "An unauthenticated attacker can retrieve all user records including email and password hashes."
        )
        confidence = 1.0 if has_taint else 0.95
        _create_chain_to_datastore(auth_uid, ds_uid, evidence, confidence=confidence)
        _annotate_reachable(auth_uid, reachable=True, from_public=True)
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

def _create_chain_to_datastore(
    finding_uid: str,
    datastore_uid: str,
    evidence: str,
    confidence: float = 0.8,
) -> None:
    """Create a :CHAINS_TO edge from a Finding node to a DataStore node."""
    run_write(
        """
        MATCH (f:Finding {uid: $finding_uid})
        MATCH (d:DataStore {uid: $datastore_uid})
        MERGE (f)-[r:CHAINS_TO]->(d)
        SET r.evidence = $evidence, r.confidence = $confidence
        """,
        {
            "finding_uid": finding_uid,
            "datastore_uid": datastore_uid,
            "evidence": evidence,
            "confidence": confidence,
        },
    )


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
