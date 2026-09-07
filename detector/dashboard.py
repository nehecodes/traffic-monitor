"""
dashboard.py — FastAPI server exposing /api/metrics and serving the
live metrics UI at /.

Pydantic models enforce the response schema.
Uvicorn runs in a daemon thread so main.py owns the process loop.
Static files (index.html) are served from ./static relative to this file's
directory — works both locally and inside the Docker container.
"""

import os
import time
import threading
from collections import Counter
from typing import Optional

import psutil
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import monitor
from . import baseline
from . import blocker

# ── Pydantic models ───────────────────────────────────────────────────────────


class IPCount(BaseModel):
    ip: str
    count: int


class BannedIP(BaseModel):
    ip: str
    banned_at: float
    tier: int
    permanent: bool
    remaining_seconds: Optional[int] = None


class BaselineStats(BaseModel):
    mean: float
    stddev: float
    error_mean: float
    error_stddev: float
    sample_count: int
    last_recalc: float


class SystemStats(BaseModel):
    cpu_percent: float
    mem_percent: float
    mem_used_mb: float
    mem_total_mb: float


class MetricsResponse(BaseModel):
    uptime_seconds: int
    global_rps: float
    top_ips: list[IPCount]
    banned_ips: list[BannedIP]
    baseline: BaselineStats
    system: SystemStats
    timestamp: float


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(title="Norma — Traffic Monitor")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)

_start_time = time.time()


@app.get("/api/metrics", response_model=MetricsResponse)
def metrics() -> MetricsResponse:
    now = time.time()

    with monitor.state_lock:
        global_rps = round(len(monitor.global_window) / 60.0, 2)
        ip_counts: Counter = Counter()
        for ts, ip in monitor.global_window:
            ip_counts[ip] += 1
        top_ips = [IPCount(ip=ip, count=cnt) for ip, cnt in ip_counts.most_common(10)]

    s = baseline.get_stats()
    cpu = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory()
    bans = blocker.get_bans()

    return MetricsResponse(
        uptime_seconds=int(now - _start_time),
        global_rps=global_rps,
        top_ips=top_ips,
        banned_ips=[BannedIP(**b) for b in bans],
        baseline=BaselineStats(
            mean=round(s["mean"], 2),
            stddev=round(s["stddev"], 2),
            error_mean=round(s["error_mean"], 2),
            error_stddev=round(s["error_stddev"], 2),
            sample_count=s["sample_count"],
            last_recalc=s["last_recalc"],
        ),
        system=SystemStats(
            cpu_percent=cpu,
            mem_percent=mem.percent,
            mem_used_mb=round(mem.used / 1024 / 1024, 1),
            mem_total_mb=round(mem.total / 1024 / 1024, 1),
        ),
        timestamp=now,
    )


_static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
app.mount("/", StaticFiles(directory=_static_dir, html=True), name="static")


def start(host: str = "0.0.0.0", port: int = 8080) -> None:
    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)
    threading.Thread(target=server.run, daemon=True, name="dashboard").start()
