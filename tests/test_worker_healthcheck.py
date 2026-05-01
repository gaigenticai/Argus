"""Audit F4 — worker heartbeat healthcheck."""

from __future__ import annotations

import os
import time

from src.workers.healthcheck import main as healthcheck_main


def test_healthcheck_fresh(tmp_path, monkeypatch):
    p = tmp_path / "hb"
    p.write_text(str(int(time.time())))
    monkeypatch.setenv("ARGUS_WORKER_HEARTBEAT", str(p))
    monkeypatch.setenv("ARGUS_WORKER_HEARTBEAT_MAX_AGE", "600")
    assert healthcheck_main() == 0


def test_healthcheck_stale(tmp_path, monkeypatch):
    p = tmp_path / "hb"
    p.write_text(str(int(time.time()) - 9999))
    monkeypatch.setenv("ARGUS_WORKER_HEARTBEAT", str(p))
    monkeypatch.setenv("ARGUS_WORKER_HEARTBEAT_MAX_AGE", "60")
    assert healthcheck_main() == 1


def test_healthcheck_missing_file(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_WORKER_HEARTBEAT", str(tmp_path / "nope"))
    assert healthcheck_main() == 1
