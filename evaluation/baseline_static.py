"""Baseline static analysis evaluation — P5.5

Runs Bandit on the vulnerable Flask fixture and compares results against
the ground truth findings. Documents what static tools miss (particularly
CWE-306 missing auth and all 3 vulnerability chains).

Usage:
    python evaluation/baseline_static.py
    python evaluation/baseline_static.py --json   # emit raw JSON
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from evaluation.ground_truth import (
    GROUND_TRUTH_CHAINS,
    GROUND_TRUTH_FINDINGS,
    GTFinding,
    contextual_severity_upgrades,
    findings_detectable_by_static,
    findings_requiring_postura,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FIXTURE_DIR = Path(__file__).parent.parent / "tests" / "fixtures" / "vulnerable_flask_app"

# Bandit severity → normalised label mapping
_BANDIT_SEV_MAP = {"LOW": "LOW", "MEDIUM": "MEDIUM", "HIGH": "HIGH"}

# Map ground-truth finding IDs to Bandit test IDs (best-effort)
# Bandit may not cover all findings; omitted IDs are "not detected"
_GT_TO_BANDIT_TEST: dict[str, list[str]] = {
    "F1": ["B608"],          # SQL injection via string formatting
    "F2": [],                # CWE-306 missing auth — no Bandit test
    "F3": ["B310"],          # url-open audit
    "F4": ["B105", "B106"],  # hardcoded password / secret
    "F5": ["B104"],          # binding to all interfaces (debug proxy)
    "F6": [],                # dependency CVEs — pip-audit only
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class BanditFinding:
    """A single Bandit result."""
    test_id: str
    test_name: str
    severity: str      # LOW / MEDIUM / HIGH
    confidence: str    # LOW / MEDIUM / HIGH
    filename: str
    line_number: int
    issue_text: str
    more_info: str = ""


@dataclass
class MatchResult:
    """Outcome of matching a GT finding against Bandit output."""
    gt_id: str
    detected: bool
    bandit_severity: str | None       # severity Bandit assigned (if detected)
    expected_raw_severity: str        # GT raw severity
    expected_contextual_severity: str # GT contextual severity
    severity_underrated: bool         # bandit_severity < expected_raw_severity
    notes: str = ""


# ---------------------------------------------------------------------------
# Bandit runner
# ---------------------------------------------------------------------------

def run_bandit(target: Path) -> list[BanditFinding]:
    """Run Bandit on *target* directory and return parsed findings."""
    cmd = [
        sys.executable, "-m", "bandit",
        "-r", str(target),
        "-f", "json",
        "-q",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except FileNotFoundError:
        print("ERROR: bandit not found. Install with: pip install bandit", file=sys.stderr)
        return []
    except subprocess.TimeoutExpired:
        print("ERROR: bandit timed out", file=sys.stderr)
        return []

    # Bandit exits 1 when findings exist — that's normal
    raw = proc.stdout.strip()
    if not raw:
        return []

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        print(f"ERROR: could not parse bandit output:\n{raw[:500]}", file=sys.stderr)
        return []

    findings = []
    for r in data.get("results", []):
        findings.append(BanditFinding(
            test_id=r.get("test_id", ""),
            test_name=r.get("test_name", ""),
            severity=r.get("issue_severity", "").upper(),
            confidence=r.get("issue_confidence", "").upper(),
            filename=Path(r.get("filename", "")).name,
            line_number=r.get("line_number", 0),
            issue_text=r.get("issue_text", ""),
            more_info=r.get("more_info", ""),
        ))
    return findings


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

_SEV_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _is_underrated(bandit_sev: str | None, expected: str) -> bool:
    if bandit_sev is None:
        return False
    return _SEV_ORDER.get(bandit_sev, 0) < _SEV_ORDER.get(expected, 0)


def match_findings(bandit_findings: list[BanditFinding]) -> list[MatchResult]:
    """Map each ground-truth finding to detection status."""
    # Index bandit findings by test_id
    by_test: dict[str, list[BanditFinding]] = {}
    for bf in bandit_findings:
        by_test.setdefault(bf.test_id, []).append(bf)

    results = []
    for gtf in GROUND_TRUTH_FINDINGS:
        test_ids = _GT_TO_BANDIT_TEST.get(gtf.id, [])
        matched_bandit: BanditFinding | None = None
        for tid in test_ids:
            if tid in by_test:
                matched_bandit = by_test[tid][0]
                break

        detected = matched_bandit is not None
        bandit_sev = matched_bandit.severity if matched_bandit else None

        underrated = _is_underrated(bandit_sev, gtf.raw_severity)

        notes = ""
        if not gtf.detectable_by_static:
            notes = "Not detectable by static analysis — requires POSTURA contextual reasoning."
        elif not detected:
            notes = f"No Bandit test covers {gtf.cwe_id or 'this pattern'}."
        elif underrated:
            diff = _SEV_ORDER[gtf.raw_severity] - _SEV_ORDER[bandit_sev]
            notes = (
                f"Bandit rates {bandit_sev}, GT raw is {gtf.raw_severity} "
                f"({diff} level{'s' if diff > 1 else ''} underrated). "
                f"Contextual severity is {gtf.contextual_severity}."
            )

        results.append(MatchResult(
            gt_id=gtf.id,
            detected=detected,
            bandit_severity=bandit_sev,
            expected_raw_severity=gtf.raw_severity,
            expected_contextual_severity=gtf.contextual_severity,
            severity_underrated=underrated,
            notes=notes,
        ))
    return results


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

@dataclass
class BaselineMetrics:
    total_gt_findings: int
    detected_count: int          # static tool found it (any severity)
    missed_count: int            # not detected at all
    underrated_count: int        # detected but severity underrated
    chains_detected: int         # chains a static tool can reconstruct
    chains_total: int
    detection_rate: float        # detected_count / total_gt_findings
    chain_detection_rate: float
    match_results: list[MatchResult] = field(default_factory=list)
    bandit_findings: list[BanditFinding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "total_gt_findings": self.total_gt_findings,
            "detected_count": self.detected_count,
            "missed_count": self.missed_count,
            "underrated_count": self.underrated_count,
            "chains_detected": self.chains_detected,
            "chains_total": self.chains_total,
            "detection_rate": round(self.detection_rate, 3),
            "chain_detection_rate": round(self.chain_detection_rate, 3),
            "match_results": [
                {
                    "gt_id": m.gt_id,
                    "detected": m.detected,
                    "bandit_severity": m.bandit_severity,
                    "expected_raw_severity": m.expected_raw_severity,
                    "expected_contextual_severity": m.expected_contextual_severity,
                    "severity_underrated": m.severity_underrated,
                    "notes": m.notes,
                }
                for m in self.match_results
            ],
            "bandit_raw_count": len(self.bandit_findings),
        }


def compute_metrics(
    bandit_findings: list[BanditFinding],
    match_results: list[MatchResult],
) -> BaselineMetrics:
    detected = sum(1 for m in match_results if m.detected)
    missed = sum(1 for m in match_results if not m.detected)
    underrated = sum(1 for m in match_results if m.severity_underrated)

    # Static tools can detect individual findings but CANNOT reconstruct chains
    # because chains require:
    #   (a) missing-auth detection (F2 — impossible for static)
    #   (b) graph-path reasoning across endpoint→function→data-store
    # All 3 chains require POSTURA.
    chains_detected = 0  # static tools cannot reconstruct any chain
    chains_total = len(GROUND_TRUTH_CHAINS)

    return BaselineMetrics(
        total_gt_findings=len(GROUND_TRUTH_FINDINGS),
        detected_count=detected,
        missed_count=missed,
        underrated_count=underrated,
        chains_detected=chains_detected,
        chains_total=chains_total,
        detection_rate=detected / len(GROUND_TRUTH_FINDINGS),
        chain_detection_rate=0.0,
        match_results=match_results,
        bandit_findings=bandit_findings,
    )


# ---------------------------------------------------------------------------
# Report printer
# ---------------------------------------------------------------------------

def print_report(metrics: BaselineMetrics) -> None:
    W = 72
    print("=" * W)
    print("POSTURA — Baseline Static Analysis Evaluation")
    print("Tool: Bandit  |  Target: tests/fixtures/vulnerable_flask_app")
    print("=" * W)

    print("\n── Bandit Raw Findings ──────────────────────────────────────────")
    if not metrics.bandit_findings:
        print("  (none found — is bandit installed in the venv?)")
    for bf in metrics.bandit_findings:
        sev_tag = f"[{bf.severity}/{bf.confidence}]"
        print(f"  {sev_tag:<15} {bf.test_id}  {bf.filename}:{bf.line_number}")
        print(f"    {bf.issue_text[:70]}")

    print("\n── Ground Truth ↔ Bandit Match ──────────────────────────────────")
    header = f"  {'ID':<6} {'Detected':<10} {'Bandit Sev':<12} {'GT Raw':<10} {'GT Ctx':<10}"
    print(header)
    print("  " + "-" * (len(header) - 2))
    for m in metrics.match_results:
        det_str = "YES" if m.detected else "NO "
        bsev = m.bandit_severity or "—"
        flag = " ⚠ UNDERRATED" if m.severity_underrated else ""
        flag += " ✗ MISSED" if not m.detected else ""
        print(
            f"  {m.gt_id:<6} {det_str:<10} {bsev:<12} "
            f"{m.expected_raw_severity:<10} {m.expected_contextual_severity:<10}{flag}"
        )
        if m.notes:
            print(f"    → {m.notes}")

    print("\n── Contextual Severity Upgrades (missed by static) ──────────────")
    upgrades = contextual_severity_upgrades()
    if not upgrades:
        print("  (none)")
    for gtf, raw, ctx in upgrades:
        print(f"  {gtf.id} ({gtf.cwe_id or 'n/a'}): {raw} → {ctx}  [{gtf.title}]")
    print("  Static tools report raw severity only; context requires POSTURA.")

    print("\n── Chain Detection ──────────────────────────────────────────────")
    for chain in GROUND_TRUTH_CHAINS:
        print(f"  {chain.id}: {chain.title}")
        print(f"    Findings: {', '.join(chain.finding_ids)}")
        print(f"    Static: NOT DETECTED — {chain.notes[:80]}")

    print("\n── Summary Metrics ──────────────────────────────────────────────")
    total = metrics.total_gt_findings
    print(f"  GT findings total      : {total}")
    print(f"  Detected by Bandit     : {metrics.detected_count}/{total}  ({metrics.detection_rate:.0%})")
    print(f"  Missed entirely        : {metrics.missed_count}/{total}")
    print(f"  Severity underrated    : {metrics.underrated_count}/{metrics.detected_count} detected")
    print(f"  Chains detected        : {metrics.chains_detected}/{metrics.chains_total}  (0%)")
    print()
    print("  Key gaps static tools cannot close:")
    for gtf in findings_requiring_postura():
        print(f"    • {gtf.id} ({gtf.cwe_id}): {gtf.title}")
    print("    • All 3 vulnerability chains (require graph path reasoning)")
    print("    • Contextual severity upgrades (require endpoint/datastore context)")
    print("=" * W)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_baseline_eval(target: Path = FIXTURE_DIR) -> BaselineMetrics:
    bandit_findings = run_bandit(target)
    match_results = match_findings(bandit_findings)
    return compute_metrics(bandit_findings, match_results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run baseline static analysis evaluation")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of human report")
    parser.add_argument("--fixture", default=str(FIXTURE_DIR), help="Path to fixture directory")
    args = parser.parse_args()

    metrics = run_baseline_eval(Path(args.fixture))

    if args.json:
        print(json.dumps(metrics.to_dict(), indent=2))
    else:
        print_report(metrics)

    # Exit code: 0 = ran OK (regardless of findings)
    sys.exit(0)
