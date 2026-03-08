"""Rule-based contextual severity scoring (P2.7a) and posture score (P2.7b).

Contextual severity rules:
  - Reachable from public + no auth + touches PII → raise by 2 (max CRITICAL)
  - Reachable from public + no auth               → raise by 1
  - Behind strong auth + internal only            → lower by 1
  - Part of a CHAINS_TO chain                     → raise by 1

Posture score:
  score = 100 - weighted_sum(open findings by contextual_severity)
  Weights: CRITICAL=10, HIGH=5, MEDIUM=2, LOW=1, INFO=0
  Normalized to 0–100.
"""
from __future__ import annotations

import logging
from postura.graph.connection import run_query, run_write

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
_SEVERITY_INDEX = {s: i for i, s in enumerate(_SEVERITY_ORDER)}


def _raise_severity(current: str, levels: int) -> str:
    idx = _SEVERITY_INDEX.get(current, 2)
    return _SEVERITY_ORDER[min(idx + levels, 4)]


def _lower_severity(current: str, levels: int) -> str:
    idx = _SEVERITY_INDEX.get(current, 2)
    return _SEVERITY_ORDER[max(idx - levels, 0)]


def score_all_findings() -> int:
    """
    Apply contextual severity rules to all open findings.
    Updates contextual_severity on each Finding node.
    Returns the number of findings updated.
    """
    findings = run_query(
        """
        MATCH (f:Finding {status: 'open'})
        RETURN f.uid AS uid, f.raw_severity AS raw_severity,
               f.contextual_severity AS current_contextual,
               f.reachable_from_public AS reachable_public
        """
    )

    updated = 0
    for row in findings:
        uid = row["uid"]
        raw = row["raw_severity"] or "LOW"
        new_severity = _compute_contextual_severity(uid, raw)

        old = row["current_contextual"] or raw
        if new_severity != old:
            run_write(
                "MATCH (f:Finding {uid: $uid}) SET f.contextual_severity = $sev",
                {"uid": uid, "sev": new_severity},
            )
            updated += 1

    logger.info("Contextual severity: updated %d of %d findings", updated, len(findings))
    return updated


def _compute_contextual_severity(finding_uid: str, raw_severity: str) -> str:
    """Apply rules to compute contextual severity for a single finding."""
    context = _get_finding_context(finding_uid)
    severity = raw_severity

    reachable_public = context.get("reachable_public") or False
    auth_level = context.get("auth_level") or 0           # 0=none, 1=basic, 2=strong
    touches_pii = context.get("touches_pii") or False
    in_chain = context.get("in_chain") or False
    is_public_endpoint = context.get("is_public_endpoint") or False

    # Rule: public + no auth + PII → +2
    if (reachable_public or is_public_endpoint) and auth_level == 0 and touches_pii:
        severity = _raise_severity(severity, 2)
    # Rule: public + no auth → +1
    elif (reachable_public or is_public_endpoint) and auth_level == 0:
        severity = _raise_severity(severity, 1)
    # Rule: strong auth + internal → -1
    elif auth_level >= 2 and not reachable_public:
        severity = _lower_severity(severity, 1)

    # Rule: part of a chain → +1
    if in_chain:
        severity = _raise_severity(severity, 1)

    return severity


def _get_finding_context(finding_uid: str) -> dict:
    """
    Query the graph for contextual factors about a finding:
    - Is it reachable from a public endpoint?
    - What auth level protects it?
    - Does it touch a PII datastore?
    - Is it part of a chain?
    """
    results = run_query(
        """
        MATCH (f:Finding {uid: $uid})

        // Check if in a chain
        OPTIONAL MATCH (f)-[:CHAINS_TO|CHAINS_TO*]-()
        WITH f, count(*) > 0 AS in_chain

        // Find the affected node (Function or Endpoint)
        OPTIONAL MATCH (f)-[:AFFECTS]->(target)

        // Endpoint context: is this finding on or reachable from a public endpoint?
        OPTIONAL MATCH (ep:Endpoint)-[:HANDLED_BY]->(target)
        OPTIONAL MATCH (ep2:Endpoint {is_public: true})-[:HANDLED_BY]->(h:Function)-[:CALLS*0..5]->(target)
        WITH f, in_chain, target, ep, ep2,
             coalesce(ep.is_public, false) OR (ep2 IS NOT NULL) AS reachable_public,
             coalesce(ep.auth_required, false) AS ep_auth

        // Auth level from trust zone
        OPTIONAL MATCH (ep)-[:IN_ZONE]->(tz:TrustZone)
        OPTIONAL MATCH (ep2)-[:IN_ZONE]->(tz2:TrustZone)
        WITH f, in_chain, reachable_public, ep_auth,
             coalesce(tz.level, tz2.level, 0) AS zone_level,
             target

        // PII exposure: does the target function access a PII datastore?
        OPTIONAL MATCH (target)-[:READS_FROM|WRITES_TO]->(ds:DataStore {contains_pii: true})
        OPTIONAL MATCH (target2:Function)-[:CALLS*0..3]->(target3:Function)-[:READS_FROM|WRITES_TO]->(ds2:DataStore {contains_pii: true})
        WHERE target2 = target OR target3 = target

        RETURN in_chain,
               reachable_public,
               ep_auth,
               zone_level,
               ep_auth = false AND reachable_public AS is_public_endpoint,
               CASE zone_level
                   WHEN 2 THEN 2
                   WHEN 3 THEN 2
                   WHEN 1 THEN 1
                   ELSE CASE WHEN ep_auth THEN 1 ELSE 0 END
               END AS auth_level,
               (ds IS NOT NULL OR ds2 IS NOT NULL) AS touches_pii
        LIMIT 1
        """,
        {"uid": finding_uid},
    )

    if not results:
        return {}

    row = results[0]
    return {
        "in_chain": bool(row.get("in_chain")),
        "reachable_public": bool(row.get("reachable_public")),
        "auth_level": int(row.get("auth_level") or 0),
        "touches_pii": bool(row.get("touches_pii")),
        "is_public_endpoint": bool(row.get("is_public_endpoint")),
    }


def compute_posture_score() -> float:
    """
    Aggregate posture score: 100 = no findings, 0 = maximum risk.

    Uses per-finding average severity so the score reflects *quality* rather
    than raw finding count. A codebase with 1000 LOW findings scores better
    than one with 5 CRITICAL findings.

    avg_risk = total_weighted_risk / finding_count
    score    = 100 * exp(-avg_risk / SEVERITY_SCALE)

    SEVERITY_SCALE = 5 means:
      - avg risk = 5 (all HIGH)  → score ~37
      - avg risk = 2 (all MEDIUM)→ score ~67
      - avg risk = 1 (all LOW)   → score ~82
      - avg risk = 0 (no findings)→ score 100

    Weights: CRITICAL=10, HIGH=5, MEDIUM=2, LOW=1
    """
    import math

    _SEVERITY_SCALE = 5.0

    results = run_query(
        """
        MATCH (f:Finding {status: 'open'})
        WITH sum(
            CASE f.contextual_severity
                WHEN 'CRITICAL' THEN 10
                WHEN 'HIGH'     THEN 5
                WHEN 'MEDIUM'   THEN 2
                WHEN 'LOW'      THEN 1
                ELSE 0
            END
        ) AS risk_score,
        count(f) AS total_findings
        RETURN risk_score, total_findings
        """
    )
    if not results:
        return 100.0
    risk = float(results[0].get("risk_score") or 0)
    total = float(results[0].get("total_findings") or 0)
    if total == 0:
        return 100.0
    avg_risk = risk / total
    return round(100.0 * math.exp(-avg_risk / _SEVERITY_SCALE), 1)


def get_finding_severity_distribution() -> dict[str, int]:
    """Return count of open findings per contextual severity."""
    results = run_query(
        """
        MATCH (f:Finding {status: 'open'})
        RETURN f.contextual_severity AS severity, count(f) AS cnt
        ORDER BY cnt DESC
        """
    )
    return {r["severity"]: r["cnt"] for r in results if r.get("severity")}
