"""POSTURA evaluation against ground truth — P5.5

Queries a live Neo4j graph (populated by running POSTURA against the
vulnerable Flask fixture) and compares what POSTURA found vs. the
ground truth.

Usage:
    # 1. Start Neo4j and ingest the fixture first:
    #    python -m postura.ingest.cli tests/fixtures/vulnerable_flask_app
    # 2. Run evaluation:
    PYTHONPATH=. python evaluation/postura_eval.py
    PYTHONPATH=. python evaluation/postura_eval.py --json
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field

from evaluation.ground_truth import (
    GROUND_TRUTH_CHAINS,
    GROUND_TRUTH_FINDINGS,
    GTChain,
    GTFinding,
    contextual_severity_upgrades,
    findings_requiring_postura,
)

# ---------------------------------------------------------------------------
# Graph queries
# ---------------------------------------------------------------------------

def _get_graph_connection():
    """Import Neo4j connection lazily (allows import without Neo4j running)."""
    from postura.graph.connection import run_query
    return run_query


def _query_findings(run_query) -> list[dict]:
    """Fetch all Finding nodes from the graph."""
    rows = run_query(
        """
        MATCH (f:Finding)
        RETURN f.uid AS uid,
               f.cwe_id AS cwe_id,
               f.title AS title,
               f.file AS file,
               f.raw_severity AS raw_severity,
               f.contextual_severity AS contextual_severity,
               f.status AS status
        ORDER BY f.contextual_severity DESC
        """
    )
    return [dict(r) for r in rows]


def _query_chains(run_query) -> list[dict]:
    """Fetch all vulnerability chains via CHAINS_TO edges between Finding nodes."""
    rows = run_query(
        """
        MATCH (f1:Finding)-[r:CHAINS_TO]->(f2:Finding)
        RETURN f1.uid AS from_uid,
               f1.title AS from_title,
               f1.cwe_id AS from_cwe,
               f2.uid AS to_uid,
               f2.title AS to_title,
               f2.cwe_id AS to_cwe,
               r.chain_type AS chain_type,
               r.confidence AS confidence
        """
    )
    return [dict(r) for r in rows]


def _query_severity_upgrades(run_query) -> list[dict]:
    """Fetch findings where contextual_severity != raw_severity."""
    rows = run_query(
        """
        MATCH (f:Finding)
        WHERE f.raw_severity <> f.contextual_severity
        RETURN f.uid AS uid,
               f.cwe_id AS cwe_id,
               f.title AS title,
               f.raw_severity AS raw_severity,
               f.contextual_severity AS contextual_severity
        """
    )
    return [dict(r) for r in rows]


def _query_public_endpoints(run_query) -> int:
    """Count public unauthenticated endpoints."""
    rows = run_query(
        """
        MATCH (e:Endpoint {is_public: true, auth_required: false})
        RETURN count(e) AS cnt
        """
    )
    if rows:
        return rows[0].get("cnt", 0)
    return 0


# ---------------------------------------------------------------------------
# Matching helpers
# ---------------------------------------------------------------------------

_SEV_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

_GT_CWE_SET = {gtf.cwe_id for gtf in GROUND_TRUTH_FINDINGS if gtf.cwe_id}
_GT_CHAIN_KEYWORDS = {
    "Chain-A": ["supply", "cve", "dependency"],
    "Chain-B": ["sql", "injection", "pii", "login"],
    "Chain-C": ["auth", "admin", "pii"],
}


def _matches_gt_finding(graph_f: dict, gtf: GTFinding) -> bool:
    """Heuristic: does a graph finding match a GT finding?"""
    # CWE match is the strongest signal
    if gtf.cwe_id and graph_f.get("cwe_id") == gtf.cwe_id:
        return True
    # File match + partial title keyword
    if gtf.file and graph_f.get("file", "").endswith(gtf.file):
        title_lower = (graph_f.get("title") or "").lower()
        gt_words = [w.lower() for w in gtf.title.split() if len(w) > 4]
        if any(w in title_lower for w in gt_words):
            return True
    return False


def _matches_gt_chain(edge: dict, chain: GTChain) -> bool:
    """Heuristic: does a CHAINS_TO edge match a GT chain?

    Matches against from_title, to_title, chain_type using keyword list.
    """
    haystack = " ".join([
        (edge.get("from_title") or ""),
        (edge.get("to_title") or ""),
        (edge.get("chain_type") or ""),
        (edge.get("from_cwe") or ""),
        (edge.get("to_cwe") or ""),
    ]).lower()
    keywords = _GT_CHAIN_KEYWORDS.get(chain.id, [])
    return any(k in haystack for k in keywords)


# ---------------------------------------------------------------------------
# Evaluation result types
# ---------------------------------------------------------------------------

@dataclass
class FindingMatchResult:
    gt_id: str
    gt_cwe: str | None
    gt_title: str
    detected: bool
    contextual_severity_correct: bool | None  # None if not detected
    contextual_severity_postura: str | None
    expected_contextual_severity: str
    notes: str = ""


@dataclass
class ChainMatchResult:
    gt_chain_id: str
    gt_title: str
    detected: bool
    notes: str = ""


@dataclass
class PosturaMetrics:
    total_gt_findings: int
    detected_count: int
    missed_count: int
    severity_correct_count: int    # contextual severity matches GT exactly
    severity_upgraded_count: int   # POSTURA upgraded vs raw (correct direction)
    chains_detected: int
    chains_total: int
    public_unauth_endpoints: int
    detection_rate: float
    chain_detection_rate: float
    severity_accuracy: float       # % contextual severity correct (of detected)
    graph_findings_total: int      # total findings in graph (may differ from GT)
    graph_chains_total: int
    finding_results: list[FindingMatchResult] = field(default_factory=list)
    chain_results: list[ChainMatchResult] = field(default_factory=list)
    upgrade_results: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "total_gt_findings": self.total_gt_findings,
            "detected_count": self.detected_count,
            "missed_count": self.missed_count,
            "severity_correct_count": self.severity_correct_count,
            "severity_upgraded_count": self.severity_upgraded_count,
            "chains_detected": self.chains_detected,
            "chains_total": self.chains_total,
            "public_unauth_endpoints": self.public_unauth_endpoints,
            "detection_rate": round(self.detection_rate, 3),
            "chain_detection_rate": round(self.chain_detection_rate, 3),
            "severity_accuracy": round(self.severity_accuracy, 3),
            "graph_findings_total": self.graph_findings_total,
            "graph_chains_total": self.graph_chains_total,
            "finding_results": [
                {
                    "gt_id": r.gt_id,
                    "gt_cwe": r.gt_cwe,
                    "detected": r.detected,
                    "contextual_severity_correct": r.contextual_severity_correct,
                    "contextual_severity_postura": r.contextual_severity_postura,
                    "expected_contextual_severity": r.expected_contextual_severity,
                    "notes": r.notes,
                }
                for r in self.finding_results
            ],
            "chain_results": [
                {"gt_chain_id": r.gt_chain_id, "detected": r.detected, "notes": r.notes}
                for r in self.chain_results
            ],
            "upgrade_results": self.upgrade_results,
        }


# ---------------------------------------------------------------------------
# Core evaluation logic
# ---------------------------------------------------------------------------

def evaluate_postura(run_query=None) -> PosturaMetrics:
    if run_query is None:
        run_query = _get_graph_connection()

    graph_findings = _query_findings(run_query)
    graph_chains = _query_chains(run_query)
    graph_upgrades = _query_severity_upgrades(run_query)
    public_unauth = _query_public_endpoints(run_query)

    # --- Match each GT finding ---
    finding_results: list[FindingMatchResult] = []
    for gtf in GROUND_TRUTH_FINDINGS:
        matched = [gf for gf in graph_findings if _matches_gt_finding(gf, gtf)]
        if matched:
            gf = matched[0]
            postura_ctx_sev = gf.get("contextual_severity")
            correct = postura_ctx_sev == gtf.contextual_severity
            notes = ""
            if not correct:
                notes = (
                    f"POSTURA: {postura_ctx_sev}, expected: {gtf.contextual_severity}"
                )
            finding_results.append(FindingMatchResult(
                gt_id=gtf.id,
                gt_cwe=gtf.cwe_id,
                gt_title=gtf.title,
                detected=True,
                contextual_severity_correct=correct,
                contextual_severity_postura=postura_ctx_sev,
                expected_contextual_severity=gtf.contextual_severity,
                notes=notes,
            ))
        else:
            notes = ""
            if not gtf.detectable_by_static:
                notes = "Expected POSTURA-only detection — CHECK chain rules."
            finding_results.append(FindingMatchResult(
                gt_id=gtf.id,
                gt_cwe=gtf.cwe_id,
                gt_title=gtf.title,
                detected=False,
                contextual_severity_correct=None,
                contextual_severity_postura=None,
                expected_contextual_severity=gtf.contextual_severity,
                notes=notes,
            ))

    # --- Match each GT chain ---
    chain_results: list[ChainMatchResult] = []
    for chain in GROUND_TRUTH_CHAINS:
        matched = [gc for gc in graph_chains if _matches_gt_chain(gc, chain)]
        detected = bool(matched)
        notes = ""
        if not detected:
            notes = "Chain not found in graph — check chain_discovery rules."
        chain_results.append(ChainMatchResult(
            gt_chain_id=chain.id,
            gt_title=chain.title,
            detected=detected,
            notes=notes,
        ))

    # --- Severity upgrade assessment ---
    gt_upgrades = contextual_severity_upgrades()
    upgrade_results = []
    for gtf, raw_sev, ctx_sev in gt_upgrades:
        postura_upgraded = any(
            gu.get("cwe_id") == gtf.cwe_id
            for gu in graph_upgrades
            if gtf.cwe_id
        )
        upgrade_results.append({
            "gt_id": gtf.id,
            "raw_severity": raw_sev,
            "expected_ctx_severity": ctx_sev,
            "postura_upgraded": postura_upgraded,
        })

    # --- Aggregate metrics ---
    detected_count = sum(1 for r in finding_results if r.detected)
    missed_count = len(finding_results) - detected_count
    detected_results = [r for r in finding_results if r.detected]
    severity_correct = sum(1 for r in detected_results if r.contextual_severity_correct)
    severity_upgraded = sum(
        1 for u in upgrade_results if u["postura_upgraded"]
    )
    chains_detected = sum(1 for r in chain_results if r.detected)

    sev_acc = severity_correct / detected_count if detected_count > 0 else 0.0
    chain_rate = chains_detected / len(GROUND_TRUTH_CHAINS) if GROUND_TRUTH_CHAINS else 0.0

    return PosturaMetrics(
        total_gt_findings=len(GROUND_TRUTH_FINDINGS),
        detected_count=detected_count,
        missed_count=missed_count,
        severity_correct_count=severity_correct,
        severity_upgraded_count=severity_upgraded,
        chains_detected=chains_detected,
        chains_total=len(GROUND_TRUTH_CHAINS),
        public_unauth_endpoints=public_unauth,
        detection_rate=detected_count / len(GROUND_TRUTH_FINDINGS),
        chain_detection_rate=chain_rate,
        severity_accuracy=sev_acc,
        graph_findings_total=len(graph_findings),
        graph_chains_total=len(graph_chains),
        finding_results=finding_results,
        chain_results=chain_results,
        upgrade_results=upgrade_results,
    )


# ---------------------------------------------------------------------------
# Report printer
# ---------------------------------------------------------------------------

def print_report(metrics: PosturaMetrics) -> None:
    W = 72
    print("=" * W)
    print("POSTURA — Agent Evaluation vs Ground Truth")
    print("Target: tests/fixtures/vulnerable_flask_app")
    print("=" * W)

    print("\n── Finding Detection ────────────────────────────────────────────")
    header = f"  {'ID':<6} {'Detected':<10} {'POSTURA Ctx':<14} {'GT Ctx':<10} {'Correct'}"
    print(header)
    print("  " + "-" * (len(header) - 2))
    for r in metrics.finding_results:
        det_str = "YES" if r.detected else "NO "
        psev = r.contextual_severity_postura or "—"
        correct_str = ""
        if r.detected:
            correct_str = "✓" if r.contextual_severity_correct else "✗"
        print(
            f"  {r.gt_id:<6} {det_str:<10} {psev:<14} "
            f"{r.expected_contextual_severity:<10} {correct_str}"
        )
        if r.notes:
            print(f"    → {r.notes}")

    print("\n── Chain Detection ──────────────────────────────────────────────")
    for r in metrics.chain_results:
        det_str = "YES ✓" if r.detected else "NO  ✗"
        print(f"  {r.gt_chain_id:<10} {det_str}  {r.gt_title}")
        if r.notes:
            print(f"    → {r.notes}")

    print("\n── Contextual Severity Upgrades ─────────────────────────────────")
    for u in metrics.upgrade_results:
        upgraded = "✓ UPGRADED" if u["postura_upgraded"] else "✗ NOT upgraded"
        print(
            f"  {u['gt_id']}: {u['raw_severity']} → {u['expected_ctx_severity']}  {upgraded}"
        )

    print("\n── Public Unauthenticated Endpoints ─────────────────────────────")
    print(f"  Found: {metrics.public_unauth_endpoints}")
    print("  (Ground truth: /admin/users and /fetch are public+unauth)")

    print("\n── Summary Metrics ──────────────────────────────────────────────")
    total = metrics.total_gt_findings
    print(f"  GT findings total          : {total}")
    print(f"  POSTURA detected           : {metrics.detected_count}/{total}  ({metrics.detection_rate:.0%})")
    print(f"  Missed                     : {metrics.missed_count}/{total}")
    print(
        f"  Contextual severity correct: "
        f"{metrics.severity_correct_count}/{metrics.detected_count}  "
        f"({metrics.severity_accuracy:.0%} of detected)"
    )
    print(
        f"  Severity upgraded (of {len(metrics.upgrade_results)} expected)"
        f"          : {metrics.severity_upgraded_count}"
    )
    print(f"  Chains detected            : {metrics.chains_detected}/{metrics.chains_total}  ({metrics.chain_detection_rate:.0%})")
    print(f"  Graph finding nodes total  : {metrics.graph_findings_total}")
    print(f"  Graph chain nodes total    : {metrics.graph_chains_total}")
    print("=" * W)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run POSTURA evaluation against ground truth")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of human report")
    args = parser.parse_args()

    try:
        metrics = evaluate_postura()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        print("Is Neo4j running and the fixture ingested?", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(json.dumps(metrics.to_dict(), indent=2))
    else:
        print_report(metrics)

    sys.exit(0)
