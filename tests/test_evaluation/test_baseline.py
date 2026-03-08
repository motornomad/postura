"""Unit tests for the evaluation baseline — P5.5

All tests are offline (no Neo4j, no network). Bandit output is mocked.
"""
from __future__ import annotations

import pytest
from unittest.mock import patch

from evaluation.ground_truth import (
    GROUND_TRUTH_FINDINGS,
    GROUND_TRUTH_CHAINS,
    findings_detectable_by_static,
    findings_requiring_postura,
    contextual_severity_upgrades,
)
from evaluation.baseline_static import (
    BanditFinding,
    MatchResult,
    match_findings,
    compute_metrics,
    run_baseline_eval,
    _is_underrated,
)


# ---------------------------------------------------------------------------
# Ground truth helpers
# ---------------------------------------------------------------------------

class TestGroundTruth:
    def test_total_findings_count(self):
        assert len(GROUND_TRUTH_FINDINGS) == 6

    def test_total_chains_count(self):
        assert len(GROUND_TRUTH_CHAINS) == 3

    def test_detectable_by_static(self):
        static = findings_detectable_by_static()
        ids = [f.id for f in static]
        assert "F1" in ids
        assert "F3" in ids
        assert "F4" in ids
        assert "F5" in ids
        assert "F6" in ids
        # F2 (missing auth) is NOT static-detectable
        assert "F2" not in ids

    def test_postura_only_findings(self):
        postura_only = findings_requiring_postura()
        assert len(postura_only) == 1
        assert postura_only[0].id == "F2"
        assert postura_only[0].cwe_id == "CWE-306"

    def test_contextual_upgrades(self):
        upgrades = contextual_severity_upgrades()
        upgrade_ids = [gtf.id for gtf, _, _ in upgrades]
        # F1 HIGH→CRITICAL, F2 HIGH→CRITICAL, F3 HIGH→CRITICAL, F5 MEDIUM→HIGH
        assert "F1" in upgrade_ids
        assert "F2" in upgrade_ids
        assert "F3" in upgrade_ids
        assert "F5" in upgrade_ids
        # F4 is already CRITICAL raw and contextual (no upgrade)
        assert "F4" not in upgrade_ids

    def test_all_findings_have_ids(self):
        for f in GROUND_TRUTH_FINDINGS:
            assert f.id.startswith("F")

    def test_all_chains_have_ids(self):
        for c in GROUND_TRUTH_CHAINS:
            assert c.id.startswith("Chain-")

    def test_finding_frozen(self):
        f = GROUND_TRUTH_FINDINGS[0]
        with pytest.raises(Exception):  # frozen dataclass
            f.id = "X"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Severity ordering helpers
# ---------------------------------------------------------------------------

class TestSeverityOrdering:
    def test_low_underrated_vs_medium(self):
        assert _is_underrated("LOW", "MEDIUM") is True

    def test_medium_underrated_vs_high(self):
        assert _is_underrated("MEDIUM", "HIGH") is True

    def test_low_underrated_vs_critical(self):
        assert _is_underrated("LOW", "CRITICAL") is True

    def test_same_not_underrated(self):
        assert _is_underrated("HIGH", "HIGH") is False

    def test_higher_not_underrated(self):
        assert _is_underrated("CRITICAL", "HIGH") is False

    def test_none_not_underrated(self):
        assert _is_underrated(None, "HIGH") is False


# ---------------------------------------------------------------------------
# Bandit result matching
# ---------------------------------------------------------------------------

# Realistic bandit findings for the fixture
_REAL_BANDIT_FINDINGS = [
    BanditFinding(
        test_id="B104", test_name="hardcoded_bind_all_interfaces",
        severity="MEDIUM", confidence="MEDIUM",
        filename="app.py", line_number=61,
        issue_text="Possible binding to all interfaces.",
    ),
    BanditFinding(
        test_id="B105", test_name="hardcoded_password_string",
        severity="LOW", confidence="MEDIUM",
        filename="config.py", line_number=3,
        issue_text="Possible hardcoded password: 'super_secret_123'",
    ),
    BanditFinding(
        test_id="B608", test_name="hardcoded_sql_expressions",
        severity="MEDIUM", confidence="LOW",
        filename="db.py", line_number=14,
        issue_text="Possible SQL injection via string-based query.",
    ),
    BanditFinding(
        test_id="B310", test_name="audit_url_open",
        severity="MEDIUM", confidence="HIGH",
        filename="utils.py", line_number=7,
        issue_text="Audit url open for permitted schemes.",
    ),
]


class TestMatchFindings:
    def test_f1_sql_injection_detected(self):
        results = match_findings(_REAL_BANDIT_FINDINGS)
        f1 = next(r for r in results if r.gt_id == "F1")
        assert f1.detected is True
        assert f1.bandit_severity == "MEDIUM"

    def test_f1_severity_underrated(self):
        results = match_findings(_REAL_BANDIT_FINDINGS)
        f1 = next(r for r in results if r.gt_id == "F1")
        # GT raw is HIGH, Bandit gives MEDIUM
        assert f1.severity_underrated is True

    def test_f2_missing_auth_not_detected(self):
        results = match_findings(_REAL_BANDIT_FINDINGS)
        f2 = next(r for r in results if r.gt_id == "F2")
        assert f2.detected is False
        assert f2.bandit_severity is None

    def test_f3_ssrf_detected(self):
        results = match_findings(_REAL_BANDIT_FINDINGS)
        f3 = next(r for r in results if r.gt_id == "F3")
        assert f3.detected is True

    def test_f4_hardcoded_secret_severely_underrated(self):
        results = match_findings(_REAL_BANDIT_FINDINGS)
        f4 = next(r for r in results if r.gt_id == "F4")
        assert f4.detected is True
        assert f4.bandit_severity == "LOW"
        # GT raw is CRITICAL — 3 levels underrated
        assert f4.severity_underrated is True

    def test_f5_debug_mode_detected(self):
        results = match_findings(_REAL_BANDIT_FINDINGS)
        f5 = next(r for r in results if r.gt_id == "F5")
        assert f5.detected is True

    def test_f5_not_underrated(self):
        # F5 raw is MEDIUM, Bandit gives MEDIUM — not underrated
        results = match_findings(_REAL_BANDIT_FINDINGS)
        f5 = next(r for r in results if r.gt_id == "F5")
        assert f5.severity_underrated is False

    def test_f6_dep_cves_not_detected(self):
        results = match_findings(_REAL_BANDIT_FINDINGS)
        f6 = next(r for r in results if r.gt_id == "F6")
        assert f6.detected is False

    def test_all_six_findings_covered(self):
        results = match_findings(_REAL_BANDIT_FINDINGS)
        assert len(results) == 6
        gt_ids = {r.gt_id for r in results}
        assert gt_ids == {"F1", "F2", "F3", "F4", "F5", "F6"}


class TestComputeMetrics:
    def _get_metrics(self):
        match_results = match_findings(_REAL_BANDIT_FINDINGS)
        return compute_metrics(_REAL_BANDIT_FINDINGS, match_results)

    def test_detected_count(self):
        m = self._get_metrics()
        assert m.detected_count == 4  # F1, F3, F4, F5

    def test_missed_count(self):
        m = self._get_metrics()
        assert m.missed_count == 2  # F2, F6

    def test_underrated_count(self):
        m = self._get_metrics()
        assert m.underrated_count == 3  # F1 (MEDIUM vs HIGH), F3 (MEDIUM vs HIGH), F4 (LOW vs CRITICAL)

    def test_chains_detected_zero(self):
        m = self._get_metrics()
        assert m.chains_detected == 0
        assert m.chains_total == 3

    def test_chain_detection_rate_zero(self):
        m = self._get_metrics()
        assert m.chain_detection_rate == 0.0

    def test_detection_rate(self):
        m = self._get_metrics()
        assert abs(m.detection_rate - 4/6) < 0.001

    def test_to_dict_structure(self):
        m = self._get_metrics()
        d = m.to_dict()
        assert "total_gt_findings" in d
        assert "detected_count" in d
        assert "missed_count" in d
        assert "chains_detected" in d
        assert "detection_rate" in d
        assert "match_results" in d
        assert len(d["match_results"]) == 6


class TestRunBaselineEval:
    def test_run_baseline_eval_mocked(self):
        """run_baseline_eval works with mocked bandit output."""
        with patch("evaluation.baseline_static.run_bandit", return_value=_REAL_BANDIT_FINDINGS):
            metrics = run_baseline_eval()
        assert metrics.detected_count == 4
        assert metrics.missed_count == 2
        assert metrics.chains_detected == 0

    def test_run_with_no_bandit_findings(self):
        with patch("evaluation.baseline_static.run_bandit", return_value=[]):
            metrics = run_baseline_eval()
        assert metrics.detected_count == 0
        assert metrics.detection_rate == 0.0
