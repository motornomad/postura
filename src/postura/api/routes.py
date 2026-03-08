"""REST API routes — P4/P5"""
from __future__ import annotations

from fastapi import APIRouter, Query, BackgroundTasks
from fastapi.responses import JSONResponse

from postura.graph.connection import run_query
from postura.graph.queries import (
    get_all_findings, get_posture_score, get_public_endpoints,
    get_chains, get_finding_context, get_dependency_blast_radius,
)
from postura.reasoning.severity_scorer import (
    compute_posture_score, get_finding_severity_distribution,
)

router = APIRouter(prefix="/api/v1")


@router.get("/posture")
def get_current_posture() -> dict:
    """Current posture score + finding summary."""
    score = compute_posture_score()
    distribution = get_finding_severity_distribution()
    return {
        "score": round(score, 1),
        "max_score": 100,
        "finding_counts": distribution,
        "interpretation": _interpret_score(score),
    }


@router.get("/findings")
def list_findings(
    status: str = Query("open", enum=["open", "resolved", "suppressed", "stale"]),
    severity: str | None = Query(None),
) -> list[dict]:
    """List all findings with optional filters."""
    findings = get_all_findings(status=status)
    result = []
    for row in findings:
        f = dict(row.get("f", {}))
        if severity and f.get("contextual_severity") != severity:
            continue
        result.append(f)
    return result


@router.get("/findings/{uid}")
def get_finding(uid: str) -> dict:
    """Finding detail with graph context."""
    context = get_finding_context(uid)
    if not context:
        return JSONResponse({"error": "Not found"}, status_code=404)
    return {k: dict(v) if hasattr(v, "items") else v for k, v in context.items()}


@router.get("/findings/{uid}/chains")
def get_finding_chains(uid: str) -> list[dict]:
    """All vulnerability chains involving a specific finding."""
    from postura.reasoning.chain_discovery import get_chains_for_finding
    return get_chains_for_finding(uid)


@router.get("/endpoints")
def list_endpoints() -> list[dict]:
    """All endpoints with exposure level and auth status."""
    results = run_query(
        """
        MATCH (e:Endpoint)
        OPTIONAL MATCH (e)-[:IN_ZONE]->(tz:TrustZone)
        RETURN e.uid AS uid, e.path AS path, e.method AS method,
               e.is_public AS is_public, e.auth_required AS auth_required,
               e.auth_type AS auth_type, e.framework AS framework,
               tz.name AS trust_zone, tz.level AS trust_level
        ORDER BY e.is_public DESC, e.path
        """
    )
    return [dict(r) for r in results]


@router.get("/chains")
def list_chains() -> list[dict]:
    """All vulnerability chains."""
    return get_chains()


@router.get("/diff/{commit_sha}")
def get_diff(commit_sha: str) -> dict:
    """Graph diff summary for a specific commit (findings introduced/resolved)."""
    introduced = run_query(
        "MATCH (f:Finding {introduced_in: $sha}) RETURN f",
        {"sha": commit_sha},
    )
    resolved = run_query(
        "MATCH (f:Finding {resolved_in: $sha}) RETURN f",
        {"sha": commit_sha},
    )
    return {
        "commit_sha": commit_sha,
        "introduced": [dict(r.get("f", {})) for r in introduced],
        "resolved": [dict(r.get("f", {})) for r in resolved],
    }


@router.get("/dependencies/{name}/blast-radius")
def dependency_blast_radius(name: str) -> dict:
    """Blast radius of a compromised dependency."""
    return get_dependency_blast_radius(name) or {"error": f"Dependency '{name}' not found"}


# ---------------------------------------------------------------------------
# P5.3 — Dashboard / reporting
# ---------------------------------------------------------------------------

@router.get("/dashboard")
def get_dashboard() -> dict:
    """Top-level dashboard: posture score, trend, top risks, chain count."""
    score = compute_posture_score()
    distribution = get_finding_severity_distribution()

    from postura.delivery.history import get_posture_trend, get_top_risk_findings
    trend = get_posture_trend(window=10)
    top_risks = get_top_risk_findings(limit=5)

    chain_count = len(get_chains())

    return {
        "posture": {
            "score": round(score, 1),
            "max_score": 100,
            "interpretation": _interpret_score(score),
            "finding_counts": distribution,
        },
        "trend": {
            "direction": trend.get("trend", "unknown"),
            "delta": trend.get("delta", 0),
            "current_score": trend.get("current_score", round(score, 1)),
            "previous_score": trend.get("previous_score"),
        },
        "top_risks": top_risks,
        "chain_count": chain_count,
    }


@router.get("/history")
def posture_history(
    limit: int = Query(50, ge=1, le=200),
    repo: str = Query("", description="Filter by repo full name"),
) -> list[dict]:
    """Time-series posture history (most recent first)."""
    from postura.delivery.history import get_posture_history
    return get_posture_history(limit=limit, repo=repo)


@router.get("/trend")
def posture_trend(
    window: int = Query(10, ge=2, le=100),
    repo: str = Query("", description="Filter by repo full name"),
) -> dict:
    """Posture trend analysis over the last N snapshots."""
    from postura.delivery.history import get_posture_trend
    return get_posture_trend(window=window, repo=repo)


# ---------------------------------------------------------------------------
# P5.2 — Natural language query
# ---------------------------------------------------------------------------

@router.post("/query")
def nl_query(body: dict) -> dict:
    """
    Answer a freeform natural language question about the security graph.

    Body: {"question": "What's our most critical vulnerability chain?"}

    Returns: {answer, cypher, raw_results, result_count}
    """
    question = (body.get("question") or "").strip()
    if not question:
        return JSONResponse({"error": "question is required"}, status_code=422)
    if len(question) > 1000:
        return JSONResponse({"error": "question too long (max 1000 chars)"}, status_code=422)

    from postura.api.nl_query import answer_question
    result = answer_question(question)
    return result.to_dict()


@router.post("/knowledge/reload")
def reload_knowledge(
    background_tasks: BackgroundTasks,
    sources: str = Query("owasp", description="Comma-separated: owasp,cwe,cve"),
) -> dict:
    """Reload knowledge base collections. CWE download is slow — runs in background."""
    requested = {s.strip().lower() for s in sources.split(",")}

    def _reload() -> None:
        if "owasp" in requested:
            from postura.knowledge.owasp_loader import load_owasp_knowledge
            load_owasp_knowledge(force_reload=True)
        if "cwe" in requested:
            from postura.knowledge.cwe_loader import load_cwe_knowledge
            load_cwe_knowledge(force_reload=True)
        if "cve" in requested:
            from postura.knowledge.cve_loader import load_cve_knowledge
            load_cve_knowledge(force_reload=True)
        from postura.knowledge.retriever import invalidate_bm25_cache
        invalidate_bm25_cache()

    background_tasks.add_task(_reload)
    return {"status": "reload_started", "sources": list(requested)}


@router.get("/knowledge/status")
def knowledge_status() -> dict:
    """Return document counts for each knowledge collection."""
    from postura.knowledge.embedder import collection_count
    return {
        "cwe": collection_count("cwe"),
        "cve": collection_count("cve"),
        "owasp": collection_count("owasp"),
    }


@router.get("/knowledge/search")
def knowledge_search(
    q: str = Query(..., description="Search query"),
    k: int = Query(5, ge=1, le=20),
    sources: str | None = Query(None, description="Comma-separated: cwe,cve,owasp"),
) -> list[dict]:
    """Hybrid search across the security knowledge base."""
    from postura.reasoning.tools import knowledge_retrieve
    source_list = [s.strip() for s in sources.split(",")] if sources else None
    return knowledge_retrieve(q, k=k, sources=source_list)


@router.post("/findings/{uid}/remediate")
def remediate_finding(uid: str, additional_context: str = "") -> dict:
    """Generate an LLM-powered remediation suggestion for a finding."""
    from postura.reasoning.tools import generate_remediation
    return generate_remediation(uid, additional_context=additional_context)


def _interpret_score(score: float) -> str:
    if score >= 90:
        return "GOOD"
    elif score >= 70:
        return "FAIR"
    elif score >= 50:
        return "POOR"
    else:
        return "CRITICAL"
