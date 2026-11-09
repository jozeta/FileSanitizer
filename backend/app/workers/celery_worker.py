from celery import Celery
from app.config import settings
from app.core.job_manager import job_manager
from app.core.logging_config import logger
from app.sanitizers.base import SanitizationOptions

celery_app = Celery(
    "filesanitizer_worker",
    broker=settings.REDIS_URL or "redis://redis:6379/0",
    backend=settings.REDIS_URL or "redis://redis:6379/0"
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    worker_concurrency=4,
    task_track_started=True,
    # Per-job wall-clock ceiling: the soft limit raises SoftTimeLimitExceeded inside the
    # task, which the pipeline's except handler turns into a FAILED job (visible to the
    # API); the hard limit then force-kills a truly wedged worker process.
    task_soft_time_limit=600,   # 10 minutes
    task_time_limit=660,        # 11 minutes hard kill
    # Fairness: take one job at a time so a large APK/PCAP does not reserve a backlog and
    # starve other uploads; re-queue a job if a worker dies mid-task (pipeline is idempotent).
    worker_prefetch_multiplier=1,
    task_acks_late=True,
)

@celery_app.task(name="tasks.analyze_job")
def analyze_job(job_id: str):
    logger.info(f"[Celery Worker] Starting analysis for job {job_id}")
    job = job_manager.execute_analysis_pipeline(job_id)
    return {"job_id": job.job_id, "state": job.state, "risk": job.risk.level if job.risk else None}

@celery_app.task(name="tasks.sanitize_job")
def sanitize_job(job_id: str, options_dict: dict):
    logger.info(f"[Celery Worker] Starting sanitization for job {job_id}")
    options = SanitizationOptions(**options_dict)
    job = job_manager.execute_sanitization_pipeline(job_id, options)
    return {"job_id": job.job_id, "state": job.state, "is_clean": job.validation.get("is_clean", False) if job.validation else False}
