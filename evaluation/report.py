"""Comparison report generator — P5.5

Generates a Markdown comparison table: Bandit (static baseline) vs POSTURA.
Can run with only the static baseline (no Neo4j required) for offline use.

Usage:
    # Static-only (no Neo4j):
    PYTHONPATH=. python evaluation/report.py --static-only

    # Full comparison (requires Neo4j + ingested fixture):
    PYTHONPATH=. python evaluation/report.py

    # Save to file:
    PYTHONPATH=. python evaluation/report.py --output evaluation/REPORT.md
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from evaluation.baseline_static import run_baseline_eval, BaselineMetrics
from evaluation.ground_truth import (
    GROUND_TRUTH_CHAINS,
    GROUND_TRUTH_FINDINGS,
    contextual_severity_upgrades,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SEV_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
    None: "—",
}


def _sev(s: str | None) -> str:
    return f"{_SEV_EMOJI.get(s, '—')} {s}" if s else "—"


def _bool(b: bool | None) -> str:
    if b is None:
        return "—"
    return "✅" if b else "❌"


# ---------------------------------------------------------------------------
# Report sections
# ---------------------------------------------------------------------------

def _header() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""# POSTURA Evaluation Report

**Generated**: {ts}
**Fixture**: `tests/fixtures/vulnerable_flask_app`
**Ground truth**: 6 findings (F1–F6), 3 vulnerability chains (Chain-A/B/C)

---
"""


def _finding_table(static: BaselineMetrics, postura_metrics=None) -> str:
    rows = []
    rows.append("## Finding Detection\n")
    rows.append(
        "| ID | CWE | Title | GT Raw | GT Contextual "
        "| Bandit Detected | Bandit Severity "
        "| POSTURA Detected | POSTURA Ctx Sev |"
    )
    rows.append("|---|---|---|---|---|---|---|---|---|")

    for gtf in GROUND_TRUTH_FINDINGS:
        # Static match
        static_match = next(
            (m for m in static.match_results if m.gt_id == gtf.id), None
        )
        bandit_det = _bool(static_match.detected if static_match else False)
        bandit_sev = _sev(static_match.bandit_severity if static_match else None)

        # POSTURA match
        if postura_metrics:
            p_match = next(
                (r for r in postura_metrics.finding_results if r.gt_id == gtf.id), None
            )
            postura_det = _bool(p_match.detected if p_match else False)
            postura_ctx = _sev(p_match.contextual_severity_postura if p_match else None)
        else:
            postura_det = "*(no data)*"
            postura_ctx = "*(no data)*"

        cwe = gtf.cwe_id or "—"
        rows.append(
            f"| **{gtf.id}** | {cwe} | {gtf.title} "
            f"| {_sev(gtf.raw_severity)} | {_sev(gtf.contextual_severity)} "
            f"| {bandit_det} | {bandit_sev} "
            f"| {postura_det} | {postura_ctx} |"
        )

    rows.append("")
    return "\n".join(rows)


def _severity_upgrade_section(static: BaselineMetrics, postura_metrics=None) -> str:
    upgrades = contextual_severity_upgrades()
    rows = ["## Contextual Severity Upgrades\n"]
    rows.append(
        "Static tools report raw severity only. "
        "POSTURA upgrades severity based on endpoint exposure, "
        "datastore sensitivity, and chain membership.\n"
    )
    rows.append("| ID | CWE | Raw → Contextual | POSTURA Upgraded |")
    rows.append("|---|---|---|---|")

    for gtf, raw, ctx in upgrades:
        if postura_metrics:
            pu = next(
                (u for u in postura_metrics.upgrade_results if u["gt_id"] == gtf.id),
                None,
            )
            upgraded = _bool(pu["postura_upgraded"] if pu else False)
        else:
            upgraded = "*(no data)*"
        rows.append(
            f"| **{gtf.id}** | {gtf.cwe_id or '—'} "
            f"| {_sev(raw)} → {_sev(ctx)} | {upgraded} |"
        )

    rows.append("")
    return "\n".join(rows)


def _chain_section(postura_metrics=None) -> str:
    rows = ["## Vulnerability Chain Detection\n"]
    rows.append(
        "Chains require multi-hop graph reasoning. "
        "Static tools detect **0/3** chains by design — "
        "they have no model of endpoint exposure, call paths, or datastore sensitivity.\n"
    )
    rows.append("| Chain | Title | Bandit | POSTURA |")
    rows.append("|---|---|---|---|")

    for chain in GROUND_TRUTH_CHAINS:
        if postura_metrics:
            cr = next(
                (r for r in postura_metrics.chain_results if r.gt_chain_id == chain.id),
                None,
            )
            postura_chain = _bool(cr.detected if cr else False)
        else:
            postura_chain = "*(no data)*"

        rows.append(
            f"| **{chain.id}** | {chain.title} | ❌ | {postura_chain} |"
        )

    rows.append("")
    rows.append("> **Chain definitions**")
    for chain in GROUND_TRUTH_CHAINS:
        rows.append(f"> - **{chain.id}**: {chain.notes}")
    rows.append("")
    return "\n".join(rows)


def _summary_table(static: BaselineMetrics, postura_metrics=None) -> str:
    total = len(GROUND_TRUTH_FINDINGS)
    chains_total = len(GROUND_TRUTH_CHAINS)

    static_det = static.detected_count
    static_missed = static.missed_count
    static_chain = 0
    static_underrated = static.underrated_count

    if postura_metrics:
        p_det = postura_metrics.detected_count
        p_missed = postura_metrics.missed_count
        p_chain = postura_metrics.chains_detected
        p_sev_acc = f"{postura_metrics.severity_accuracy:.0%}"
    else:
        p_det = p_missed = p_chain = "—"
        p_sev_acc = "—"

    rows = ["## Summary Comparison\n"]
    rows.append("| Metric | Bandit (Static) | POSTURA |")
    rows.append("|---|---|---|")
    p_det_pct = f"{p_det/total:.0%}" if postura_metrics else "—"
    rows.append(f"| Findings detected (of {total}) | {static_det} ({static_det/total:.0%}) | {p_det} ({p_det_pct}) |")
    rows.append(f"| Missed findings | {static_missed} | {p_missed} |")
    rows.append(f"| Severity underrated (detected) | {static_underrated} | — |")
    rows.append(f"| Contextual severity accuracy | ❌ Not supported | {p_sev_acc} |")
    rows.append(f"| Chains detected (of {chains_total}) | 0 (0%) | {p_chain} |")
    rows.append(f"| Missing auth detection (F2) | ❌ | {'✅' if postura_metrics and any(r.gt_id == 'F2' and r.detected for r in postura_metrics.finding_results) else '—'} |")
    rows.append(f"| Supply-chain CVE reachability | ❌ | {'✅' if postura_metrics and any(r.gt_chain_id == 'Chain-A' and r.detected for r in postura_metrics.chain_results) else '—'} |")
    rows.append("")
    return "\n".join(rows)


def _gaps_section() -> str:
    return """## What Static Tools Cannot Detect

| Gap | Why Static Fails | How POSTURA Closes It |
|---|---|---|
| **F2: Missing Auth** (CWE-306) | No concept of "should have auth" | Auth graph edge absence + public endpoint flag |
| **Contextual severity** | Only sees code, not runtime topology | Graph paths: endpoint exposure × datastore sensitivity |
| **Chain-A: Supply-chain reachability** | CVE known but not call-path | USES edges: Function→Dependency + public endpoint reachability |
| **Chain-B: SQLi + PII** | B608 finds SQLi but no PII path | CHAINS_TO: Finding→DataStore with PII=true |
| **Chain-C: Auth + PII** | Missing auth undetectable | CHAINS_TO: Endpoint(unauth)→DataStore(PII) |
| **Dependency blast radius** | Not modeled | Graph traversal: Dependency→Function→Endpoint |

---

*Report generated by POSTURA evaluation framework (P5.5)*
"""


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def generate_report(postura_metrics=None) -> str:
    static = run_baseline_eval()
    sections = [
        _header(),
        _finding_table(static, postura_metrics),
        _severity_upgrade_section(static, postura_metrics),
        _chain_section(postura_metrics),
        _summary_table(static, postura_metrics),
        _gaps_section(),
    ]
    return "\n".join(sections)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate POSTURA evaluation report")
    parser.add_argument("--static-only", action="store_true", help="Skip POSTURA graph queries")
    parser.add_argument("--output", "-o", help="Output file path (default: stdout)")
    args = parser.parse_args()

    postura_metrics = None
    if not args.static_only:
        try:
            from evaluation.postura_eval import evaluate_postura
            postura_metrics = evaluate_postura()
        except Exception as exc:
            print(f"WARNING: Could not query POSTURA graph: {exc}", file=sys.stderr)
            print("Falling back to static-only report. Start Neo4j and ingest fixture first.", file=sys.stderr)

    report = generate_report(postura_metrics)

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(report)
        print(f"Report written to {out}")
    else:
        print(report)


if __name__ == "__main__":
    main()
