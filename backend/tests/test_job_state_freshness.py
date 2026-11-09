"""
PERF-02 step 1: cross-process job-state freshness.

To let analysis move off the API process onto the Celery worker, the API must be
able to see a job's live progress even though another process is driving it. These
tests cover the shared-state read machinery in job_manager: atomic, stamped disk
writes and get_job adopting newer on-disk state for non-final jobs.
"""

import time

from app.core.job_manager import job_manager


def _make_job():
    return job_manager.create_job(b"hello world", "freshness_probe.txt")


def _write_state(job_id, model):
    ws = job_manager.get_workspace(job_id)
    (ws.base_dir / "job_state.json").write_text(model.model_dump_json())


def test_get_job_adopts_newer_disk_state():
    """A worker in another process writes fresher progress to disk -> get_job returns it."""
    job = _make_job()
    jid = job.job_id
    try:
        cached = job_manager.get_job(jid)
        fresh = cached.model_copy(deep=True)
        fresh.state = "ANALYZING"
        fresh.progress = 77
        fresh.current_step_label = "Worker step"
        fresh.updated_at = cached.updated_at + 10.0
        _write_state(jid, fresh)

        got = job_manager.get_job(jid)
        assert got.progress == 77
        assert got.state == "ANALYZING"
    finally:
        job_manager.delete_job(jid)


def test_get_job_ignores_stale_disk_state():
    """An older on-disk write must not clobber a newer in-memory copy."""
    job = _make_job()
    jid = job.job_id
    try:
        cached = job_manager.get_job(jid)
        cached.progress = 50
        cached.updated_at = time.time() + 100.0  # cache is clearly newest

        stale = cached.model_copy(deep=True)
        stale.progress = 3
        stale.updated_at = cached.updated_at - 50.0
        _write_state(jid, stale)

        got = job_manager.get_job(jid)
        assert got.progress == 50  # kept cache, ignored older disk
    finally:
        job_manager.delete_job(jid)


def test_final_job_not_refreshed_from_disk():
    """COMPLETED/FAILED are final: the cache is authoritative even if disk looks newer."""
    job = _make_job()
    jid = job.job_id
    try:
        cached = job_manager.get_job(jid)
        cached.state = "COMPLETED"
        cached.progress = 100
        cached.updated_at = 1.0

        newer = cached.model_copy(deep=True)
        newer.state = "ANALYZING"
        newer.progress = 5
        newer.updated_at = 9_999_999_999.0
        _write_state(jid, newer)

        got = job_manager.get_job(jid)
        assert got.state == "COMPLETED"
        assert got.progress == 100
    finally:
        job_manager.delete_job(jid)


def test_save_is_atomic_and_stamped():
    """_save_job_to_disk bumps updated_at and leaves no temp files behind."""
    job = _make_job()
    jid = job.job_id
    try:
        before = time.time()
        job_manager._save_job_to_disk(job)
        assert job.updated_at >= before
        ws = job_manager.get_workspace(jid)
        assert list(ws.base_dir.glob(".job_state.*.tmp")) == []
        # the persisted file is valid, complete JSON
        import json
        data = json.loads((ws.base_dir / "job_state.json").read_text())
        assert data["job_id"] == jid
    finally:
        job_manager.delete_job(jid)
