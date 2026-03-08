"""Structured ground truth for the vulnerable Flask fixture.

Derived from tests/fixtures/vulnerable_flask_app/GROUND_TRUTH.md.
Used as the gold standard for evaluating baseline tools vs POSTURA.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class GTFinding:
    """A ground-truth vulnerability finding."""
    id: str          # F1–F6
    cwe_id: str      # e.g. "CWE-89"
    title: str
    file: str
    raw_severity: str     # expert-assigned raw severity
    contextual_severity: str  # expert-assigned after context (public endpoint + PII)
    detectable_by_static: bool  # can a static tool detect this?
    notes: str = ""


@dataclass(frozen=True)
class GTChain:
    """A ground-truth vulnerability chain."""
    id: str       # Chain A/B/C
    title: str
    finding_ids: list[str] = field(default_factory=list)
    confidence: str = "HIGH"
    notes: str = ""


# ---------------------------------------------------------------------------
# Ground truth findings
# ---------------------------------------------------------------------------

GROUND_TRUTH_FINDINGS: list[GTFinding] = [
    GTFinding(
        id="F1",
        cwe_id="CWE-89",
        title="SQL Injection via f-string in get_user_by_name",
        file="db.py",
        raw_severity="HIGH",
        contextual_severity="CRITICAL",
        detectable_by_static=True,
        notes="Bandit B608 detects this. Contextual severity is CRITICAL because "
              "it's reachable from public /login endpoint and reads PII (users table).",
    ),
    GTFinding(
        id="F2",
        cwe_id="CWE-306",
        title="Missing Authentication on /admin/users endpoint",
        file="app.py",
        raw_severity="HIGH",
        contextual_severity="CRITICAL",
        detectable_by_static=False,
        notes="Static tools cannot detect missing decorators — they don't reason about "
              "what authentication should be present. POSTURA detects via auth_required=False "
              "on public endpoint + PII datastore reachability.",
    ),
    GTFinding(
        id="F3",
        cwe_id="CWE-918",
        title="Server-Side Request Forgery in fetch_external",
        file="app.py",
        raw_severity="HIGH",
        contextual_severity="CRITICAL",
        detectable_by_static=True,
        notes="Bandit B310 detects url-open audit. Semgrep detects SSRF with appropriate rules. "
              "Contextual severity is CRITICAL because it is a public unauthenticated endpoint.",
    ),
    GTFinding(
        id="F4",
        cwe_id="CWE-798",
        title="Hardcoded Secret Key",
        file="config.py",
        raw_severity="CRITICAL",
        contextual_severity="CRITICAL",
        detectable_by_static=True,
        notes="Bandit B105 detects this but rates it LOW — severe underrating. "
              "POSTURA rates it CRITICAL (already critical raw).",
    ),
    GTFinding(
        id="F5",
        cwe_id="CWE-94",
        title="Debug Mode Enabled in Production",
        file="config.py",
        raw_severity="MEDIUM",
        contextual_severity="HIGH",
        detectable_by_static=True,
        notes="Bandit B104 detects binding to all interfaces. Config analyzer detects DEBUG=True.",
    ),
    GTFinding(
        id="F6",
        cwe_id=None,
        title="Outdated Dependencies with Known CVEs (werkzeug, requests, jinja2)",
        file="requirements.txt",
        raw_severity="HIGH",
        contextual_severity="HIGH",
        detectable_by_static=True,  # pip-audit
        notes="pip-audit detects CVEs in pinned versions. "
              "POSTURA elevates if reachable from public endpoint via USES edges.",
    ),
]

# ---------------------------------------------------------------------------
# Ground truth chains
# ---------------------------------------------------------------------------

GROUND_TRUTH_CHAINS: list[GTChain] = [
    GTChain(
        id="Chain-A",
        title="Supply-Chain CVE Reachable from Public Endpoint",
        finding_ids=["F6"],
        confidence="HIGH",
        notes="CVE on werkzeug/requests → USES edge from Function → public /fetch endpoint. "
              "Static tools detect the CVE but cannot detect reachability.",
    ),
    GTChain(
        id="Chain-B",
        title="SQL Injection + Public Endpoint + PII DataStore",
        finding_ids=["F1"],
        confidence="HIGH",
        notes="SQLi in get_user_by_name → called from /login (public) → reads users table (PII). "
              "CHAINS_TO edge from F1 → DataStore(users). "
              "No static tool produces this composite risk.",
    ),
    GTChain(
        id="Chain-C",
        title="Missing Auth + PII Data Access",
        finding_ids=["F2"],
        confidence="HIGH",
        notes="Missing auth on /admin/users → list_all_users → reads users table (PII). "
              "CHAINS_TO edge from F2 → DataStore(users). "
              "No static tool detects missing auth here at all.",
    ),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def findings_detectable_by_static() -> list[GTFinding]:
    return [f for f in GROUND_TRUTH_FINDINGS if f.detectable_by_static]


def findings_requiring_postura() -> list[GTFinding]:
    return [f for f in GROUND_TRUTH_FINDINGS if not f.detectable_by_static]


def contextual_severity_upgrades() -> list[tuple[GTFinding, str, str]]:
    """Returns (finding, raw_severity, contextual_severity) tuples where they differ."""
    return [
        (f, f.raw_severity, f.contextual_severity)
        for f in GROUND_TRUTH_FINDINGS
        if f.raw_severity != f.contextual_severity
    ]
