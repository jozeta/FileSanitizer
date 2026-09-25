import time
import threading
from datetime import datetime, timedelta
from app.config import settings
from app.core.logging_config import logger
from app.core.job_manager import job_manager

class RetentionCleaner:
    def __init__(self):
        self._running = False
        self._thread = None

    def start(self):
        if not self._running:
            self._running = True
            self._thread = threading.Thread(target=self._run_loop, daemon=True)
            self._thread.start()
            logger.info(f"Retention cleaner started (retention: {settings.FILE_RETENTION_MINUTES}m, interval: {settings.CLEANUP_INTERVAL_SECONDS}s)")

    def stop(self):
        self._running = False

    def _run_loop(self):
        while self._running:
            try:
                self.purge_expired_jobs()
            except Exception as e:
                logger.error(f"Error during retention purge: {e}")
            time.sleep(settings.CLEANUP_INTERVAL_SECONDS)

    def purge_expired_jobs(self):
        cutoff = datetime.utcnow() - timedelta(minutes=settings.FILE_RETENTION_MINUTES)
        jobs = job_manager.list_jobs()

        purged_count = 0
        for job in jobs:
            try:
                # Parse created_at ISO timestamp
                created_dt = datetime.fromisoformat(job.created_at.replace("Z", "+00:00")).replace(tzinfo=None)
                if created_dt < cutoff:
                    job_manager.delete_job(job.job_id)
                    purged_count += 1
            except Exception as e:
                logger.debug(f"Failed to check retention for job {job.job_id}: {e}")

        if purged_count > 0:
            logger.info(f"Purged {purged_count} expired job workspace(s) exceeding {settings.FILE_RETENTION_MINUTES} minutes.")

retention_cleaner = RetentionCleaner()
