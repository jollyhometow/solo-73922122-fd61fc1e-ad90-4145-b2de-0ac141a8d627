"""Web entry point: backup console, JSON API and zone file downloads.

Runs under uvicorn with two worker processes (see docker-compose.yml).  Both
workers share one SQLite database (WAL mode) and one zone-file directory on a
persistent volume; every state-changing operation uses short, self-contained
transactions so no coordination beyond SQLite's locking is required.
"""

from __future__ import annotations

import threading
from dataclasses import asdict
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

from . import config
from .service import BackupService, JobRegistry, JobView
from .storage import Storage

BASE_DIR = Path(__file__).resolve().parent

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

app = FastAPI(
    title="内网 DNS 区域认证副本备份",
    description="TSIG 认证 AXFR 区域备份与恢复控制台",
    version="1.0.0",
)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

storage = Storage(config.db_url(), config.files_dir())
registry = JobRegistry()
service = BackupService(storage, registry)
targets = {t.target_id: t for t in config.load_targets()}


def _job_dict(job: JobView) -> dict:
    data = asdict(job)
    if job.commit is not None and job.commit.stored is not None:
        data["commit"]["stored"] = asdict(job.commit.stored)
    return data


def _zone_dict(zone) -> dict:
    return {
        "name": zone.name,
        "serial": zone.serial,
        "record_count": zone.record_count,
        "message_count": zone.message_count,
        "created_at": zone.created_at,
        "updated_at": zone.updated_at,
    }


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "targets": list(targets.values()),
            "zones": storage.list_zones(),
        },
    )


@app.get("/api/targets")
def api_targets() -> JSONResponse:
    return JSONResponse(
        [
            {
                "id": t.target_id,
                "label": t.label,
                "host": t.host,
                "port": t.port,
                "zone": t.zone,
                "key_name": t.key_name,
            }
            for t in targets.values()
        ]
    )


@app.get("/api/zones")
def api_zones() -> JSONResponse:
    return JSONResponse([_zone_dict(z) for z in storage.list_zones()])


@app.get("/api/jobs")
def api_jobs() -> JSONResponse:
    return JSONResponse([_job_dict(j) for j in registry.list_jobs()])


@app.get("/api/attempts")
def api_attempts() -> JSONResponse:
    rows = storage.recent_attempts()
    return JSONResponse([dict(row) for row in rows])


@app.post("/api/backups/{target_id}")
def create_backup(target_id: str, background_tasks: BackgroundTasks) -> JSONResponse:
    target = targets.get(target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="未知的备份目标（启动配置中不存在）")
    # The transfer (up to 5 s of network waiting) runs in a worker thread
    # without holding any database write lock.
    background_tasks.add_task(service.run_backup, target)
    return JSONResponse({"accepted": True, "target_id": target_id}, status_code=202)


@app.post("/api/backups/{target_id}/sync")
def create_backup_sync(target_id: str) -> JSONResponse:
    """Synchronous variant used by the delayed-old-version demo and tests."""
    target = targets.get(target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="未知的备份目标（启动配置中不存在）")
    job = service.run_backup(target)
    return JSONResponse(_job_dict(job))


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str) -> JSONResponse:
    job = registry.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="任务不存在或已被清理")
    return JSONResponse(_job_dict(job))


@app.get("/api/zones/{name:path}/download")
def download_zone(name: str) -> Response:
    normalized = name if name.endswith(".") else name + "."
    zone = storage.get_zone(normalized)
    if zone is None:
        raise HTTPException(status_code=404, detail="该区域尚无已保存副本")
    text = storage.read_zone_file(zone)
    filename = normalized.rstrip(".").replace(".", "_") + ".zone"
    return PlainTextResponse(
        text,
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            # A version is immutable once written; never let a download mix
            # two versions through caching.
            "Cache-Control": "no-store",
        },
    )


@app.get("/healthz")
def healthz() -> JSONResponse:
    return JSONResponse({"ok": True})


# Exposed for tests that want to exercise concurrency primitives directly.
__all__ = ["app", "storage", "registry", "service", "targets"]
