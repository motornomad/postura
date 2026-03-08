"""Natural language query engine — P5.2

Accepts a freeform security question and produces a grounded answer by:
  1. Generating a read-only Cypher query from the question (LLM)
  2. Executing it against Neo4j
  3. Synthesizing a natural-language answer from the results (LLM)

Exported:
    answer_question(question) -> NLQueryResult
"""
from __future__ import annotations

import logging
import re
from typing import Any

from postura.config import settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Graph schema context fed to the LLM
# ---------------------------------------------------------------------------

_SCHEMA = """
POSTURA Threat Graph Schema
===========================

Node labels and key properties:
  :Finding        uid, title, cwe_id, raw_severity, contextual_severity, status,
                  file, line, reachable_from_public, tool, rule_id, evidence
  :Endpoint       uid, path, method, is_public, auth_required, auth_type, framework, file
  :Function       uid, name, qualified_name, file, line, module, is_entry_point,
                  handles_user_input, decorators
  :DataStore      uid, name, type, contains_pii
  :Dependency     uid, name, version, pinned, depth, known_cves
  :TrustZone      uid, name, level  (level: 0=public, 1=authenticated, 2=admin, 3=system)
  :Service        uid, name, type, exposure_level
  :PostureSnapshot uid (=commit_sha), timestamp, score, chain_count, posture_change,
                  critical_count, high_count, medium_count, low_count, repo

Relationship types:
  (Endpoint)-[:HANDLED_BY]->(Function)
  (Endpoint)-[:BELONGS_TO]->(Service)
  (Endpoint)-[:IN_ZONE]->(TrustZone)
  (Function)-[:CALLS]->(Function)
  (Function)-[:READS_FROM]->(DataStore)
  (Function)-[:WRITES_TO]->(DataStore)
  (Function)-[:USES]->(Dependency)
  (Finding)-[:AFFECTS]->(Function)
  (Finding)-[:AFFECTS]->(Dependency)
  (Finding)-[:CHAINS_TO]->(Finding)  {evidence, confidence, path_length}

Severity values: CRITICAL, HIGH, MEDIUM, LOW, INFO
Finding status values: open, resolved, suppressed, stale
"""

# ---------------------------------------------------------------------------
# Few-shot Cypher examples
# ---------------------------------------------------------------------------

_EXAMPLES = """
Examples of questions and their Cypher queries:

Q: What are the most critical open findings?
MATCH (f:Finding {status: 'open'})
RETURN f.title AS title, f.contextual_severity AS severity, f.cwe_id AS cwe_id,
       f.file AS file, f.line AS line
ORDER BY CASE f.contextual_severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
          WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END
LIMIT 10

Q: Which public endpoints have no authentication?
MATCH (e:Endpoint {is_public: true, auth_required: false})
RETURN e.path AS path, e.method AS method, e.framework AS framework, e.file AS file
ORDER BY e.path

Q: What vulnerability chains exist?
MATCH (f1:Finding)-[r:CHAINS_TO]->(f2:Finding)
RETURN f1.title AS from_finding, f2.title AS to_finding,
       r.evidence AS evidence, r.confidence AS confidence
ORDER BY r.confidence DESC

Q: What PII datastores can be reached from public endpoints?
MATCH (e:Endpoint {is_public: true})-[:HANDLED_BY]->(fn:Function)
MATCH (fn)-[:CALLS*0..5]->(g:Function)-[:READS_FROM|WRITES_TO]->(d:DataStore {contains_pii: true})
RETURN DISTINCT e.path AS endpoint, d.name AS datastore, d.type AS type

Q: What is the blast radius of the flask dependency?
MATCH (d:Dependency {name: 'flask'})
OPTIONAL MATCH (f:Function)-[:USES]->(d)
OPTIONAL MATCH (e:Endpoint)-[:HANDLED_BY]->(f)
RETURN d.name AS dep, d.version AS version, count(DISTINCT f) AS functions_using,
       count(DISTINCT e) AS exposed_endpoints, d.known_cves AS known_cves

Q: Has posture improved or degraded recently?
MATCH (s:PostureSnapshot)
RETURN s.commit_sha AS commit, s.timestamp AS timestamp, s.score AS score,
       s.posture_change AS change
ORDER BY s.timestamp DESC LIMIT 10

Q: Which functions handle user input and access the database?
MATCH (fn:Function {handles_user_input: true})
MATCH (fn)-[:READS_FROM|WRITES_TO]->(d:DataStore)
RETURN fn.qualified_name AS function, fn.file AS file,
       collect(DISTINCT d.name) AS datastores, fn.handles_user_input AS handles_input

Q: Show me all SQL injection findings.
MATCH (f:Finding {status: 'open'}) WHERE f.cwe_id = 'CWE-89' OR f.title CONTAINS 'SQL'
OPTIONAL MATCH (f)-[:AFFECTS]->(fn:Function)
RETURN f.title AS title, f.contextual_severity AS severity,
       f.file AS file, fn.qualified_name AS affected_function
"""

_WRITE_KEYWORDS = re.compile(
    r"\b(CREATE|MERGE|DELETE|DETACH|SET|REMOVE|DROP|CALL\s+db\.)\b",
    re.IGNORECASE,
)

_CYPHER_EXTRACT = re.compile(r"```(?:cypher)?\s*([\s\S]+?)```", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class NLQueryResult:
    def __init__(
        self,
        question: str,
        cypher: str,
        raw_results: list[dict],
        answer: str,
        result_count: int,
    ) -> None:
        self.question = question
        self.cypher = cypher
        self.raw_results = raw_results
        self.answer = answer
        self.result_count = result_count

    def to_dict(self) -> dict[str, Any]:
        return {
            "question": self.question,
            "answer": self.answer,
            "result_count": self.result_count,
            "cypher": self.cypher,
            "raw_results": self.raw_results[:20],   # cap for API response size
        }


def answer_question(question: str) -> NLQueryResult:
    """
    Answer a natural language question about the security posture graph.

    Args:
        question: Freeform security question in natural language.

    Returns:
        NLQueryResult with the Cypher, raw graph results, and synthesized answer.
    """
    # Step 1: Generate Cypher
    cypher = _generate_cypher(question)
    if not cypher:
        return NLQueryResult(
            question=question,
            cypher="",
            raw_results=[],
            answer="I could not generate a graph query for this question. Try rephrasing it in terms of findings, endpoints, functions, or vulnerability chains.",
            result_count=0,
        )

    # Step 2: Execute Cypher
    rows, exec_error = _execute_cypher(cypher)
    if exec_error:
        return NLQueryResult(
            question=question,
            cypher=cypher,
            raw_results=[],
            answer=f"The generated query failed to execute: {exec_error}. The graph may not have the data needed to answer this question yet.",
            result_count=0,
        )

    # Step 3: Synthesize answer
    answer = _synthesize_answer(question, cypher, rows)
    return NLQueryResult(
        question=question,
        cypher=cypher,
        raw_results=rows,
        answer=answer,
        result_count=len(rows),
    )


# ---------------------------------------------------------------------------
# Step 1: Cypher generation
# ---------------------------------------------------------------------------

def _generate_cypher(question: str) -> str:
    """Use Claude to convert a natural language question into a Cypher query."""
    prompt = (
        f"{_SCHEMA}\n\n"
        f"{_EXAMPLES}\n\n"
        "Generate a read-only Cypher MATCH query for the following question. "
        "Output ONLY the Cypher query wrapped in ```cypher ... ``` fences. "
        "The query must use only MATCH, OPTIONAL MATCH, WHERE, RETURN, ORDER BY, LIMIT, WITH. "
        "No CREATE, MERGE, SET, DELETE, REMOVE, or CALL db.* operations. "
        "Keep queries simple and targeted. Limit results to 20 rows unless the question asks for all.\n\n"
        f"Question: {question}"
    )

    raw = _llm_call(prompt, max_tokens=512)
    if not raw:
        return ""

    # Extract from code fence
    m = _CYPHER_EXTRACT.search(raw)
    cypher = m.group(1).strip() if m else raw.strip()

    # Safety check
    if _WRITE_KEYWORDS.search(cypher):
        logger.warning("LLM generated a write query — rejecting: %s", cypher[:100])
        return ""

    return cypher


# ---------------------------------------------------------------------------
# Step 2: Execute
# ---------------------------------------------------------------------------

def _execute_cypher(cypher: str) -> tuple[list[dict], str]:
    """Execute a Cypher query and return (rows, error_message)."""
    try:
        from postura.graph.connection import run_query
        rows = run_query(cypher, {})
        return [dict(r) for r in rows], ""
    except Exception as exc:
        logger.warning("Cypher execution failed: %s\nQuery: %s", exc, cypher[:200])
        return [], str(exc)


# ---------------------------------------------------------------------------
# Step 3: Answer synthesis
# ---------------------------------------------------------------------------

def _synthesize_answer(question: str, cypher: str, rows: list[dict]) -> str:
    """Use Claude to synthesize a natural-language answer from query results."""
    if not rows:
        return (
            "The query returned no results. This could mean: "
            "(1) the graph has no data matching your question yet, "
            "(2) the knowledge base needs ingestion (`POST /api/v1/knowledge/reload`), or "
            "(3) the question references entities not yet in the graph."
        )

    # Format results as a compact table
    result_text = _format_rows(rows[:15])

    prompt = (
        "You are a security analyst assistant. Answer the user's question based on "
        "the graph query results below. Be concise, specific, and reference the data directly. "
        "Highlight critical risks first. Do not mention Cypher or database internals in your answer.\n\n"
        f"Question: {question}\n\n"
        f"Query results ({len(rows)} rows):\n{result_text}\n\n"
        "Answer in 2–5 sentences. If there are actionable findings, list the top 3 specifically."
    )

    answer = _llm_call(prompt, max_tokens=512)
    return answer or _fallback_answer(rows)


def _format_rows(rows: list[dict]) -> str:
    """Format result rows as a readable text block."""
    if not rows:
        return "(no results)"
    lines = []
    for i, row in enumerate(rows, 1):
        parts = ", ".join(f"{k}={v!r}" for k, v in row.items() if v is not None)
        lines.append(f"{i}. {parts}")
    return "\n".join(lines)


def _fallback_answer(rows: list[dict]) -> str:
    """Simple fallback if LLM is unavailable."""
    return f"Found {len(rows)} result(s). Raw data: {_format_rows(rows[:5])}"


# ---------------------------------------------------------------------------
# LLM helper
# ---------------------------------------------------------------------------

def _llm_call(prompt: str, max_tokens: int = 512) -> str:
    """Make a single Claude API call. Returns response text or empty string on error."""
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=settings.llm_api_key)
        msg = client.messages.create(
            model=settings.llm_model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        return msg.content[0].text.strip()
    except Exception as exc:
        logger.error("LLM call failed in nl_query: %s", exc)
        return ""
