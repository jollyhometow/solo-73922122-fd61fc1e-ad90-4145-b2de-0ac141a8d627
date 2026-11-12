"""BackupService orchestration: failures always preserve the stored version."""

import pytest

from app.axfr_client import TransferError
from app.service import BackupService, JobRegistry
from app.storage import Storage

from .conftest import SERIAL, STALE_SERIAL, ZONE


@pytest.fixture()
def stack(tmp_path):
    storage = Storage(tmp_path / "backup.db", tmp_path / "zones")
    service = BackupService(storage, JobRegistry())
    return storage, service


def _target(port, scenario, serial_note=None):
    from app.config import Target
    from app.config import DEFAULT_KEY_NAME, DEFAULT_KEY_SECRET_B64

    return Target(
        target_id=scenario,
        label=scenario,
        host="127.0.0.1",
        port=port,
        zone=ZONE,
        key_name=DEFAULT_KEY_NAME,
        key_secret_b64=DEFAULT_KEY_SECRET_B64,
    )


def test_success_then_failure_keeps_good_version(auth_servers, stack):
    storage, service = stack
    good = _target(auth_servers["multi"], "multi")
    bad = _target(auth_servers["badsig"], "badsig")

    job = service.run_backup(good)
    assert job.state == "success"
    assert job.serial == SERIAL
    stored = storage.get_zone(ZONE)
    assert stored is not None and stored.serial == SERIAL

    failed = service.run_backup(bad)
    assert failed.state == "failed"
    assert "验签失败" in (failed.reason or "")
    # old version intact
    assert storage.get_zone(ZONE).serial == SERIAL

    # the attempt audit row captured the reason too
    attempts = storage.recent_attempts()
    reasons = [row["reason"] for row in attempts if row["ok"] == 0]
    assert any("验签失败" in r for r in reasons)


def test_truncation_and_timeout_preserve_version(auth_servers, stack):
    storage, service = stack
    service.run_backup(_target(auth_servers["multi"], "multi"))

    for scenario in ("truncated", "timeout"):
        job = service.run_backup(_target(auth_servers[scenario], scenario))
        assert job.state == "failed"
        assert storage.get_zone(ZONE).serial == SERIAL


def test_stale_complete_transfer_is_rejected_at_commit(auth_servers, stack):
    storage, service = stack
    service.run_backup(_target(auth_servers["multi"], "multi"))
    job = service.run_backup(_target(auth_servers["stale"], "stale"))
    assert job.state == "failed"
    assert "RFC 1982" in (job.reason or "") or "早于" in (job.reason or "")
    assert storage.get_zone(ZONE).serial == SERIAL
    # the transfer itself succeeded: serial was observed
    assert job.serial == STALE_SERIAL


def test_registry_tracks_job_lifecycle(auth_servers, stack):
    _, service = stack
    job = service.run_backup(_target(auth_servers["multi"], "multi"))
    assert job.finished_at is not None
    listed = service.registry.list_jobs()
    assert any(j.job_id == job.job_id and j.state == "success" for j in listed)
