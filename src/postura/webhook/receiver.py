"""GitHub webhook receiver — P3.1a

Exposes POST /webhook/github.
Verifies HMAC-SHA256 signature, classifies event, enqueues Celery task.
Returns 200 immediately (fire-and-forget async processing).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging

from fastapi import APIRouter, Header, HTTPException, Request, BackgroundTasks
from fastapi.responses import JSONResponse

from postura.config import settings
from postura.webhook.event_router import route_event, WebhookEvent

logger = logging.getLogger(__name__)

router = APIRouter()


def _verify_signature(payload: bytes, signature_header: str | None) -> bool:
    """Verify GitHub HMAC-SHA256 webhook signature."""
    if not settings.github_webhook_secret:
        # No secret configured — skip verification (dev mode only)
        logger.warning("No GITHUB_WEBHOOK_SECRET set — skipping signature verification")
        return True

    if not signature_header:
        return False

    if not signature_header.startswith("sha256="):
        return False

    expected = hmac.new(
        settings.github_webhook_secret.encode(),
        payload,
        hashlib.sha256,
    ).hexdigest()

    received = signature_header[len("sha256="):]
    return hmac.compare_digest(expected, received)


@router.post("/webhook/github")
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_github_event: str | None = Header(None),
    x_hub_signature_256: str | None = Header(None),
    x_github_delivery: str | None = Header(None),
) -> JSONResponse:
    """
    Receive and process a GitHub webhook event.

    Supported events:
    - push
    - pull_request (opened, synchronize, reopened)
    """
    payload_bytes = await request.body()

    # Signature verification
    if not _verify_signature(payload_bytes, x_hub_signature_256):
        logger.warning("Webhook signature verification failed for delivery %s", x_github_delivery)
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    # Parse payload
    try:
        payload = json.loads(payload_bytes)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    event_type = x_github_event or "unknown"
    delivery_id = x_github_delivery or "unknown"

    logger.info("Received GitHub event: %s (delivery: %s)", event_type, delivery_id)

    # Route event
    event = route_event(event_type, payload)
    if event is None:
        # Unrecognized or non-actionable event — acknowledge and ignore
        return JSONResponse({"status": "ignored", "event": event_type})

    # Enqueue async processing
    background_tasks.add_task(_process_event, event, delivery_id)

    return JSONResponse({
        "status": "accepted",
        "delivery_id": delivery_id,
        "event_type": event_type,
        "commit_sha": event.commit_sha,
        "repo": event.repo_full_name,
    })


async def _process_event(event: WebhookEvent, delivery_id: str) -> None:
    """Background: enqueue Celery task for the event."""
    try:
        from postura.tasks.analysis import analyze_commit
        task = analyze_commit.delay(
            repo_url=event.clone_url,
            commit_sha=event.commit_sha,
            changed_files=event.changed_files,
            repo_full_name=event.repo_full_name,
            pr_number=event.pr_number,
        )
        logger.info(
            "Enqueued analysis task %s for commit %s (delivery %s)",
            task.id, event.commit_sha[:8], delivery_id,
        )
    except Exception as e:
        logger.error("Failed to enqueue task for delivery %s: %s", delivery_id, e)
