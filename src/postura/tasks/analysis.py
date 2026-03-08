"""Celery task: full analysis pipeline — P3.5a + P3.5b + P4 + P5

analyze_commit: webhook → scope → ingest → graph update → diff → reasoning → delivery
"""
from __future__ import annotations

import logging
from typing import Optional

from postura.tasks import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(
    bind=True,
    max_retries=3,
    default_retry_delay=30,
    name="postura.tasks.analysis.analyze_commit",
)
def analyze_commit(
    self,
    repo_url: str,
    commit_sha: str,
    changed_files: list[str],
    repo_full_name: str = "",
    pr_number: Optional[int] = None,
) -> dict:
    """
    Full analysis pipeline for a commit/PR.

    Steps:
      1. Clone/fetch repo, checkout commit SHA
      2. Scope analysis — categorize files, expand transitive dependents
      3. Snapshot pre-update posture score
      4. Incremental graph update (soft delete → ingest → rebuild)
      5. Compute graph diff
      6. (Phase 4) Reasoning agent → PRSecurityReview
      7. (Phase 5) Post PR comment + set commit status
      8. (Phase 5) Record posture snapshot for trend tracking

    Returns a dict with task results for status tracking.
    """
    logger.info(
        "Starting analysis: %s@%s (%d changed files)",
        repo_full_name or repo_url, commit_sha[:8], len(changed_files),
    )

    try:
        # Step 1: Repo checkout
        from postura.webhook.repo_manager import get_repo_at_commit
        repo_path = get_repo_at_commit(repo_url, commit_sha)

        # Step 2: Scope analysis
        from postura.webhook.scope_analyzer import compute_scope
        from postura.reasoning.severity_scorer import compute_posture_score, get_finding_severity_distribution

        scope = compute_scope(repo_path, commit_sha)

        all_changed = list(set(changed_files) | set(scope.changed_code_files))
        affected_files = list(set(all_changed + scope.transitive_dependents))

        if not affected_files:
            logger.info("No affected files — skipping analysis for %s", commit_sha[:8])
            return {"status": "skipped", "reason": "no_affected_files"}

        # Step 3: Snapshot pre-update posture score
        prev_score = compute_posture_score()

        # Step 4: Incremental graph update
        from postura.graph.updater import update_graph_for_files
        update_result = update_graph_for_files(
            changed_files=affected_files,
            repo_path=repo_path,
            service_name=_repo_to_service_name(repo_full_name or repo_url),
        )

        # Step 5: Compute graph diff
        from postura.graph.differ import compute_graph_diff
        diff = compute_graph_diff(
            commit_sha=commit_sha,
            pre_uids=update_result["pre_uids"],
            post_uids=update_result["post_uids"],
            prev_posture_score=prev_score,
        )

        logger.info(
            "Analysis complete for %s@%s: %s",
            repo_full_name, commit_sha[:8], diff.summary,
        )

        posture_change = (
            "DEGRADED" if diff.posture_delta > 0 else
            ("IMPROVED" if diff.posture_delta < 0 else "NEUTRAL")
        )

        # Step 6: Phase 4 — reasoning agent
        review = None
        review_result = None
        if diff.new_nodes or diff.new_chains:
            try:
                from postura.reasoning.agent import run_pr_review
                new_finding_uids = [
                    n["uid"] for n in diff.new_nodes
                    if n.get("labels") and "Finding" in n.get("labels", [])
                ]
                review = run_pr_review(
                    commit_sha=commit_sha,
                    diff_summary=diff.summary,
                    pr_number=pr_number,
                    new_finding_uids=new_finding_uids or None,
                )
                review.posture_change = posture_change
                review.posture_delta = diff.posture_delta
                review_result = {
                    "risk_level": review.risk_level,
                    "requires_block": review.requires_block,
                    "top_issues": review.top_issues,
                }
                logger.info(
                    "PR review complete for %s: risk=%s block=%s",
                    commit_sha[:8], review.risk_level, review.requires_block,
                )
            except Exception as review_exc:
                logger.warning("Agent reasoning failed (non-fatal): %s", review_exc)

        # Step 7: Phase 5 — GitHub delivery (non-fatal)
        if review and repo_full_name:
            _deliver_review(repo_full_name, commit_sha, pr_number, review)

        # Step 8: Phase 5 — record posture snapshot
        try:
            from postura.delivery.history import record_snapshot
            current_score = compute_posture_score()
            finding_counts = get_finding_severity_distribution()
            chain_count = len(diff.new_chains)
            record_snapshot(
                commit_sha=commit_sha,
                score=current_score,
                finding_counts=finding_counts,
                chain_count=chain_count,
                repo=repo_full_name,
                pr_number=pr_number,
                posture_change=posture_change,
            )
        except Exception as snap_exc:
            logger.warning("Failed to record posture snapshot (non-fatal): %s", snap_exc)

        return {
            "status": "complete",
            "commit_sha": commit_sha,
            "repo": repo_full_name,
            "posture_delta": diff.posture_delta,
            "posture_change": posture_change,
            "new_findings": len(diff.new_nodes),
            "new_chains": len(diff.new_chains),
            "summary": diff.summary,
            "pr_number": pr_number,
            "review": review_result,
        }

    except Exception as exc:
        logger.error("Analysis failed for %s@%s: %s", repo_full_name, commit_sha[:8], exc)
        raise self.retry(exc=exc)


def _deliver_review(
    repo_full_name: str,
    commit_sha: str,
    pr_number: int | None,
    review,
) -> None:
    """Post PR comment and set commit status. All errors are non-fatal."""
    from postura.delivery.github import post_pr_comment, set_commit_status
    try:
        if pr_number:
            post_pr_comment(repo_full_name, pr_number, review)
        set_commit_status(repo_full_name, commit_sha, review)
    except Exception as exc:
        logger.warning("GitHub delivery failed (non-fatal): %s", exc)


def _repo_to_service_name(repo_identifier: str) -> str:
    """Extract a clean service name from a repo URL or full name."""
    name = repo_identifier.rstrip("/").rstrip(".git").split("/")[-1]
    return name or "app"
