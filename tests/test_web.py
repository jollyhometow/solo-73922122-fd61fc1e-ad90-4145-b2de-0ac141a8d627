"""Web API end-to-end tests with a real (in-process) authoritative source."""

import importlib

import pytest
from fastapi.testclient import TestClient

from app.config import DEFAULT_KEY_NAME, DEFAULT_KEY_SECRET_B64, Target

from .conftest import SERIAL, ZONE


def _target(port, scenario):
    return Target(
        target_id=scenario,
        label=f"scenario-{scenario}",
        host="127.0.0.1",
        port=port,
        zone=ZONE,
        key_name=DEFAULT_KEY_NAME,
        key_secret_b64=DEFAULT_KEY_SECRET_B64,
    )


@pytest.fixture()
def client(tmp_path, monkeypatch, auth_servers):
    monkeypatch.setenv("BACKUP_DB", str(tmp_path / "backup.db"))
    monkeypatch.setenv("BACKUP_FILES_DIR", str(tmp_path / "zones"))
    import app.main as main

    importlib.reload(main)
    main.targets.clear()
    for scenario, port in auth_servers.items():
        target = _target(port, scenario)
        main.targets[scenario] = target
    with TestClient(main.app) as test_client:
        yield test_client, main


def test_index_renders(client):
    test_client, _ = client
    resp = test_client.get("/")
    assert resp.status_code == 200
    assert "区域认证副本备份" in resp.text
    assert "multi" in resp.text


def test_targets_and_health(client):
    test_client, _ = client
    assert test_client.get("/healthz").json() == {"ok": True}
    targets = test_client.get("/api/targets").json()
    assert {t["id"] for t in targets} >= {"multi", "badsig", "truncated", "stale"}
    # secrets must never appear in the API output
    assert all("secret" not in t for t in targets)


def test_unknown_target_returns_404(client):
    test_client, _ = client
    resp = test_client.post("/api/backups/nope")
    assert resp.status_code == 404


def test_full_success_flow_and_download(client):
    test_client, main = client
    resp = test_client.post("/api/backups/multi/sync")
    assert resp.status_code == 200
    body = resp.json()
    assert body["state"] == "success"
    assert body["serial"] == SERIAL

    zones = test_client.get("/api/zones").json()
    assert len(zones) == 1 and zones[0]["serial"] == SERIAL

    download = test_client.get(f"/api/zones/{ZONE}/download")
    assert download.status_code == 200
    assert "attachment" in download.headers["content-disposition"]
    text = download.text
    assert "SOA" in text and "NS" in text and "IN\tA\t" in text
    # one coherent version only
    assert text.count(str(SERIAL)) >= 2  # appears in both SOA records


def test_failed_backup_does_not_create_zone(client):
    test_client, _ = client
    resp = test_client.post("/api/backups/badsig/sync")
    body = resp.json()
    assert body["state"] == "failed"
    assert "验签失败" in body["reason"]
    assert test_client.get("/api/zones").json() == []


def test_async_endpoint_eventually_succeeds(client):
    test_client, _ = client
    resp = test_client.post("/api/backups/multi")
    assert resp.status_code == 202
    # poll until the background thread settles
    job_state = None
    for _ in range(50):
        jobs = test_client.get("/api/jobs").json()
        if jobs and all(j["state"] != "running" for j in jobs):
            job_state = jobs[0]["state"]
            break
    assert job_state == "success"
    assert test_client.get("/api/zones").json()[0]["serial"] == SERIAL


def test_download_unknown_zone_404(client):
    test_client, _ = client
    resp = test_client.get("/api/zones/missing.test./download")
    assert resp.status_code == 404


def test_attempts_audit_endpoint(client):
    test_client, _ = client
    test_client.post("/api/backups/truncated/sync")
    attempts = test_client.get("/api/attempts").json()
    assert attempts and attempts[0]["ok"] == 0
    assert "断流" in attempts[0]["reason"]
