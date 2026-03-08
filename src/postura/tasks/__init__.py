"""Celery application factory."""
from celery import Celery
from postura.config import settings

celery_app = Celery(
    "postura",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["postura.tasks.analysis"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
)
