"""Finding, Chain, and PostureScore models."""
from pydantic import BaseModel
from typing import Optional
from .ingest import Severity


class GraphDiff(BaseModel):
    commit_sha: str
    new_nodes: list[dict] = []
    removed_nodes: list[dict] = []
    changed_nodes: list[dict] = []
    new_edges: list[dict] = []
    removed_edges: list[dict] = []
    new_chains: list[dict] = []
    broken_chains: list[dict] = []
    posture_delta: float = 0.0
    summary: str = ""


class ChainLink(BaseModel):
    finding_uid: str
    title: str
    severity: Severity
    cwe_id: Optional[str] = None


class VulnerabilityChain(BaseModel):
    chain_id: str
    links: list[ChainLink]
    overall_severity: Severity
    evidence: str
    attack_narrative: str
    remediation_priority: int = 1


class ContextualAssessment(BaseModel):
    finding_uid: str
    raw_severity: Severity
    contextual_severity: Severity
    reasoning: str
    reachable_from_public: bool
    touches_pii: bool
    auth_protection_level: int = 0           # 0=none, 1=basic, 2=strong
    in_chains: list[str] = []               # chain IDs this finding participates in


class RemediationSuggestion(BaseModel):
    finding_uid: str
    title: str
    description: str
    code_diff: Optional[str] = None
    effort_estimate: str = "medium"
    references: list[str] = []


class PRSecurityReview(BaseModel):
    commit_sha: str
    pr_number: Optional[int] = None
    posture_change: str = "NEUTRAL"         # "IMPROVED" | "DEGRADED" | "NEUTRAL"
    posture_delta: float = 0.0
    risk_level: str = "UNKNOWN"             # "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|"NONE"|"UNKNOWN"
    requires_block: bool = False            # should the PR be blocked?
    top_issues: list[str] = []             # brief issue titles from agent
    finding_count: int = 0
    critical_chains: list[VulnerabilityChain] = []
    assessments: list[ContextualAssessment] = []
    remediations: list[RemediationSuggestion] = []
    full_analysis: str = ""                 # raw agent output
    summary: str = ""


class PostureSnapshot(BaseModel):
    commit_sha: str
    timestamp: str
    score: float
    finding_counts: dict[str, int] = {}     # severity → count
    chain_count: int = 0
