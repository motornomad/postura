"""LangGraph-compatible agent tools for POSTURA — P4.3

Six tools:
    graph_query          — read-only Cypher against Neo4j
    knowledge_retrieve   — hybrid retrieval from ChromaDB knowledge base
    trace_dataflow       — call-path tracing from source to sink
    find_chains          — traverse CHAINS_TO edges from a finding
    assess_exploitability — structured exploitability context for a finding
    generate_remediation — LLM-generated fix suggestion

Each tool is a plain Python function; the LangGraph agent calls them via
ToolNode after wrapping with @tool from langchain_core.tools.
"""
from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Safety: blocked Cypher write keywords
# ---------------------------------------------------------------------------
_WRITE_KEYWORDS = re.compile(
    r"\b(CREATE|MERGE|DELETE|DETACH|SET|REMOVE|DROP|CALL\s+db\.)\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Tool 1: graph_query
# ---------------------------------------------------------------------------

def graph_query(cypher: str, params: dict | None = None) -> list[dict[str, Any]]:
    """
    Execute a read-only Cypher query against the Neo4j threat graph.

    Args:
        cypher: A MATCH/RETURN Cypher query. Write operations are rejected.
        params: Optional parameter dict for parameterized queries.

    Returns:
        List of result row dicts.

    Raises:
        ValueError: If the query contains write operations.
    """
    if _WRITE_KEYWORDS.search(cypher):
        raise ValueError(
            "graph_query only allows read operations. "
            "Write keywords detected: CREATE/MERGE/DELETE/SET/REMOVE/DROP"
        )

    from postura.graph.connection import run_query
    rows = run_query(cypher, params or {})
    # Serialize neo4j records to plain dicts
    return [dict(row) for row in rows]


# ---------------------------------------------------------------------------
# Tool 2: knowledge_retrieve
# ---------------------------------------------------------------------------

def knowledge_retrieve(
    query: str,
    k: int = 5,
    sources: list[str] | None = None,
) -> list[dict[str, Any]]:
    """
    Retrieve relevant security knowledge from the ChromaDB knowledge base.

    Args:
        query: Natural language query (e.g. "SQL injection in Flask", "CWE-89").
        k: Number of results to return (1–20).
        sources: Optional list of sources to search: "cwe", "cve", "owasp".
                 Defaults to all three.

    Returns:
        List of knowledge entry dicts with keys: id, document, metadata, score.
    """
    k = max(1, min(k, 20))
    from postura.knowledge.retriever import retrieve, retrieve_by_cwe

    # If query looks like a CWE ID, do exact lookup first
    cwe_match = re.match(r"^(CWE-?)?\d+$", query.strip(), re.IGNORECASE)
    if cwe_match and (not sources or "cwe" in sources):
        return retrieve_by_cwe(query.strip(), k=k)

    return retrieve(query, k=k, sources=sources)


# ---------------------------------------------------------------------------
# Tool 3: trace_dataflow
# ---------------------------------------------------------------------------

def trace_dataflow(
    start_uid: str,
    sink_type: str = "DataStore",
    max_hops: int = 6,
) -> list[dict[str, Any]]:
    """
    Trace call paths from a starting node (endpoint or function) to a sink node type.

    Args:
        start_uid: UID of the starting Endpoint or Function node.
        sink_type: Node label to reach (e.g. "DataStore", "Finding").
        max_hops: Maximum path length (default 6).

    Returns:
        List of path dicts, each with: path_nodes, path_uids, hops.
    """
    from postura.graph.connection import run_query

    cypher = """
    MATCH path = (start {uid: $uid})-[:HANDLED_BY|CALLS*0..$hops]->(fn:Function)
                 -[:READS_FROM|WRITES_TO]->(sink)
    WHERE $sink_type IN labels(sink)
    RETURN
        [n IN nodes(path) | coalesce(n.qualified_name, n.path, n.name, n.uid)] AS path_nodes,
        [n IN nodes(path) | n.uid] AS path_uids,
        length(path) AS hops
    ORDER BY hops
    LIMIT 20
    """
    rows = run_query(cypher, {"uid": start_uid, "hops": max_hops, "sink_type": sink_type})
    return [dict(row) for row in rows]


# ---------------------------------------------------------------------------
# Tool 4: find_chains
# ---------------------------------------------------------------------------

def find_chains(finding_uid: str | None = None) -> list[dict[str, Any]]:
    """
    Retrieve vulnerability chains from the graph.

    Args:
        finding_uid: Optional UID of a Finding node to scope the query.
                     If None, returns all chains.

    Returns:
        List of chain dicts with: from_uid, from_title, to_uid, to_title,
        evidence, confidence, path_length.
    """
    from postura.graph.connection import run_query

    if finding_uid:
        cypher = """
        MATCH (f:Finding {uid: $uid})-[r:CHAINS_TO]->(g:Finding)
        RETURN f.uid AS from_uid, f.title AS from_title,
               g.uid AS to_uid, g.title AS to_title,
               r.evidence AS evidence, r.confidence AS confidence,
               r.path_length AS path_length
        UNION
        MATCH (f:Finding)-[r:CHAINS_TO]->(g:Finding {uid: $uid})
        RETURN f.uid AS from_uid, f.title AS from_title,
               g.uid AS to_uid, g.title AS to_title,
               r.evidence AS evidence, r.confidence AS confidence,
               r.path_length AS path_length
        """
        rows = run_query(cypher, {"uid": finding_uid})
    else:
        cypher = """
        MATCH (f:Finding)-[r:CHAINS_TO]->(g:Finding)
        RETURN f.uid AS from_uid, f.title AS from_title,
               g.uid AS to_uid, g.title AS to_title,
               r.evidence AS evidence, r.confidence AS confidence,
               r.path_length AS path_length
        ORDER BY r.confidence DESC
        LIMIT 50
        """
        rows = run_query(cypher, {})

    return [dict(row) for row in rows]


# ---------------------------------------------------------------------------
# Tool 5: assess_exploitability
# ---------------------------------------------------------------------------

def assess_exploitability(finding_uid: str) -> dict[str, Any]:
    """
    Return a structured exploitability assessment for a finding.

    Queries the finding's graph neighborhood: trust zone, endpoint reachability,
    auth protection, PII exposure, chain membership.

    Args:
        finding_uid: UID of a Finding node.

    Returns:
        Dict with exploitability context fields.
    """
    from postura.graph.connection import run_query

    # Core finding + affected function
    finding_rows = run_query(
        """
        MATCH (f:Finding {uid: $uid})
        OPTIONAL MATCH (f)-[:AFFECTS]->(fn:Function)
        RETURN f.uid AS uid, f.title AS title, f.cwe_id AS cwe_id,
               f.raw_severity AS raw_severity, f.contextual_severity AS contextual_severity,
               f.status AS status, f.reachable_from_public AS reachable_from_public,
               f.file AS file, f.line AS line,
               collect(DISTINCT fn.qualified_name) AS affected_functions
        """,
        {"uid": finding_uid},
    )
    if not finding_rows:
        return {"error": f"Finding '{finding_uid}' not found"}

    ctx = dict(finding_rows[0])

    # Is it reachable from a public endpoint?
    reach_rows = run_query(
        """
        MATCH (f:Finding {uid: $uid})-[:AFFECTS]->(fn:Function)
        MATCH path = (ep:Endpoint {is_public: true})-[:HANDLED_BY|CALLS*1..6]->(fn)
        RETURN ep.path AS endpoint_path, ep.method AS method,
               ep.auth_required AS auth_required,
               length(path) AS hops
        ORDER BY hops
        LIMIT 5
        """,
        {"uid": finding_uid},
    )
    ctx["reachable_via_endpoints"] = [dict(r) for r in reach_rows]
    ctx["is_publicly_reachable"] = len(reach_rows) > 0

    # PII datastores accessible from the affected functions
    pii_rows = run_query(
        """
        MATCH (f:Finding {uid: $uid})-[:AFFECTS]->(fn:Function)
        MATCH (fn)-[:READS_FROM|WRITES_TO]->(ds:DataStore {contains_pii: true})
        RETURN DISTINCT ds.name AS datastore, ds.type AS datastore_type,
               ds.contains_pii AS pii
        LIMIT 5
        """,
        {"uid": finding_uid},
    )
    ctx["pii_datastores"] = [dict(r) for r in pii_rows]
    ctx["exposes_pii"] = len(pii_rows) > 0

    # Trust zone
    zone_rows = run_query(
        """
        MATCH (f:Finding {uid: $uid})-[:AFFECTS]->(fn:Function)
        MATCH (ep:Endpoint)-[:HANDLED_BY]->(fn)-[:IN_ZONE]->(tz:TrustZone)
        RETURN DISTINCT tz.name AS zone, tz.level AS level
        LIMIT 3
        """,
        {"uid": finding_uid},
    )
    # Alternatively check endpoint trust zone
    if not zone_rows:
        zone_rows = run_query(
            """
            MATCH (f:Finding {uid: $uid})-[:AFFECTS]->(fn:Function)
            MATCH (ep:Endpoint)-[:HANDLED_BY]->(fn)
            MATCH (ep)-[:IN_ZONE]->(tz:TrustZone)
            RETURN DISTINCT tz.name AS zone, tz.level AS level
            LIMIT 3
            """,
            {"uid": finding_uid},
        )
    ctx["trust_zones"] = [dict(r) for r in zone_rows]
    ctx["lowest_trust_zone"] = min(
        (r["level"] for r in zone_rows if r.get("level") is not None),
        default=None,
    )

    # Chain membership
    chain_rows = run_query(
        """
        MATCH (f:Finding {uid: $uid})-[r:CHAINS_TO]->(g:Finding)
        RETURN count(r) AS outbound_chains
        """,
        {"uid": finding_uid},
    )
    ctx["outbound_chains"] = chain_rows[0]["outbound_chains"] if chain_rows else 0
    ctx["in_chain"] = ctx["outbound_chains"] > 0

    return ctx


# ---------------------------------------------------------------------------
# Tool 6: generate_remediation
# ---------------------------------------------------------------------------

def generate_remediation(
    finding_uid: str,
    additional_context: str = "",
) -> dict[str, Any]:
    """
    Generate a remediation suggestion for a finding using the Claude API.

    Fetches the finding's exploitability context, retrieves relevant CWE/OWASP
    knowledge, and asks Claude to produce a specific, actionable fix.

    Args:
        finding_uid: UID of the Finding node to remediate.
        additional_context: Optional extra context (e.g. code snippet, PR diff).

    Returns:
        Dict with: finding_uid, cwe_id, remediation (text), references (list).
    """
    from postura.config import settings

    # Gather context
    ctx = assess_exploitability(finding_uid)
    if "error" in ctx:
        return ctx

    cwe_id = ctx.get("cwe_id") or ""

    # Retrieve relevant knowledge
    knowledge_docs = []
    if cwe_id:
        knowledge_docs.extend(knowledge_retrieve(cwe_id, k=2, sources=["cwe"]))
    knowledge_docs.extend(
        knowledge_retrieve(ctx.get("title", "security vulnerability"), k=2, sources=["owasp"])
    )

    knowledge_text = "\n\n".join(
        f"[{doc['id']}] {doc['document'][:600]}" for doc in knowledge_docs
    )

    prompt = _build_remediation_prompt(ctx, knowledge_text, additional_context)

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=settings.llm_api_key)
        message = client.messages.create(
            model=settings.llm_model,
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        remediation_text = message.content[0].text
    except Exception as exc:
        logger.error("LLM call failed in generate_remediation: %s", exc)
        remediation_text = f"(LLM unavailable: {exc})"

    return {
        "finding_uid": finding_uid,
        "title": ctx.get("title"),
        "cwe_id": cwe_id,
        "contextual_severity": ctx.get("contextual_severity"),
        "remediation": remediation_text,
        "references": [doc["id"] for doc in knowledge_docs],
    }


def _build_remediation_prompt(
    ctx: dict[str, Any],
    knowledge_text: str,
    additional_context: str,
) -> str:
    endpoints = ctx.get("reachable_via_endpoints", [])
    ep_desc = (
        ", ".join(f"{e.get('method')} {e.get('endpoint_path')}" for e in endpoints[:3])
        if endpoints
        else "not directly reachable from a public endpoint"
    )
    pii = ctx.get("pii_datastores", [])
    pii_desc = ", ".join(d.get("datastore", "") for d in pii) if pii else "none detected"
    affected_fns = ", ".join(ctx.get("affected_functions") or [])
    extra = f"ADDITIONAL CONTEXT:\n{additional_context}" if additional_context else ""

    return (
        "You are a senior application security engineer. Generate a specific, actionable remediation "
        "for the following vulnerability.\n\n"
        f"FINDING:\n"
        f"  Title: {ctx.get('title')}\n"
        f"  CWE: {ctx.get('cwe_id')}\n"
        f"  File: {ctx.get('file')}:{ctx.get('line')}\n"
        f"  Contextual severity: {ctx.get('contextual_severity')}\n"
        f"  Affected functions: {affected_fns}\n\n"
        f"RISK CONTEXT:\n"
        f"  Publicly reachable via: {ep_desc}\n"
        f"  PII datastores exposed: {pii_desc}\n"
        f"  In vulnerability chain: {ctx.get('in_chain')}\n\n"
        f"RELEVANT SECURITY KNOWLEDGE:\n{knowledge_text}\n\n"
        f"{extra}\n\n"
        "Provide:\n"
        "1. A one-sentence root cause explanation\n"
        "2. A concrete code-level fix (show before/after if applicable)\n"
        "3. Any configuration or architectural changes needed\n"
        "4. Testing steps to verify the fix\n\n"
        "Be specific to the file and function identified above. Do not give generic advice."
    )
