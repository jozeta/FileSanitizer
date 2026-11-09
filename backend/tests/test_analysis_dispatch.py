"""
PERF-02 step 3: analysis dispatch routing.

dispatch_analysis prefers the Celery worker, honours the ANALYSIS_DISPATCH mode,
and falls back to in-process BackgroundTasks when the broker cannot be reached,
so an upload is never silently stuck.
"""

import app.workers.celery_worker as cw
from app.config import settings
from app.core import job_manager as jm_mod


class _FakeBackgroundTasks:
    def __init__(self):
        self.calls = []

    def add_task(self, fn, *args):
        self.calls.append((fn, args))


def test_inprocess_mode_runs_in_background_tasks(monkeypatch):
    monkeypatch.setattr(settings, "ANALYSIS_DISPATCH", "inprocess")
    bg = _FakeBackgroundTasks()
    assert jm_mod.dispatch_analysis("job-ip", bg) == "inprocess"
    assert len(bg.calls) == 1
    assert bg.calls[0][1] == ("job-ip",)


def test_celery_mode_dispatches_to_worker(monkeypatch):
    monkeypatch.setattr(settings, "ANALYSIS_DISPATCH", "celery")
    sent = {}
    monkeypatch.setattr(cw.celery_app, "send_task",
                        lambda name, args=None, **k: sent.update(name=name, args=args))
    bg = _FakeBackgroundTasks()
    assert jm_mod.dispatch_analysis("job-cel", bg) == "celery"
    assert sent == {"name": "tasks.analyze_job", "args": ["job-cel"]}
    assert bg.calls == []  # not run in-process


def test_celery_failure_falls_back_in_process(monkeypatch):
    monkeypatch.setattr(settings, "ANALYSIS_DISPATCH", "celery")

    def _boom(*a, **k):
        raise RuntimeError("broker unreachable")

    monkeypatch.setattr(cw.celery_app, "send_task", _boom)
    bg = _FakeBackgroundTasks()
    assert jm_mod.dispatch_analysis("job-fb", bg) == "inprocess"
    assert len(bg.calls) == 1  # fell back so the job still runs


class _Opts:
    def model_dump(self):
        return {"profile": "privacy"}


def test_sanitization_inprocess_mode(monkeypatch):
    monkeypatch.setattr(settings, "ANALYSIS_DISPATCH", "inprocess")
    bg = _FakeBackgroundTasks()
    opts = _Opts()
    assert jm_mod.dispatch_sanitization("job-s", opts, bg) == "inprocess"
    assert len(bg.calls) == 1
    assert bg.calls[0][1] == ("job-s", opts)  # options passed through, not serialized


def test_sanitization_celery_sends_serialized_options(monkeypatch):
    monkeypatch.setattr(settings, "ANALYSIS_DISPATCH", "celery")
    sent = {}
    monkeypatch.setattr(cw.celery_app, "send_task",
                        lambda name, args=None, **k: sent.update(name=name, args=args))
    bg = _FakeBackgroundTasks()
    assert jm_mod.dispatch_sanitization("job-sc", _Opts(), bg) == "celery"
    assert sent == {"name": "tasks.sanitize_job", "args": ["job-sc", {"profile": "privacy"}]}
    assert bg.calls == []


def test_sanitization_celery_failure_falls_back(monkeypatch):
    monkeypatch.setattr(settings, "ANALYSIS_DISPATCH", "celery")

    def _boom(*a, **k):
        raise RuntimeError("broker unreachable")

    monkeypatch.setattr(cw.celery_app, "send_task", _boom)
    bg = _FakeBackgroundTasks()
    assert jm_mod.dispatch_sanitization("job-sfb", _Opts(), bg) == "inprocess"
    assert len(bg.calls) == 1
