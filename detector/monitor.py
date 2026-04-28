"""
monitor.py — Tails the nginx JSON access log and feeds parsed entries
into the shared sliding-window state.

JSON log fields (must match nginx log_format json_hng):
  source_ip, timestamp, method, path, status, response_size

Persistent offset, rotation/deletion/truncation recovery, no line cap.
"""

import json
import os
import time
import threading
from collections import deque
from datetime import datetime

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ── Shared state ──────────────────────────────────────────────────────────────

global_window: deque = deque()
ip_windows: dict[str, deque] = {}
ip_error_windows: dict[str, deque] = {}
global_error_window: deque = deque()
state_lock = threading.Lock()

WINDOW_SECONDS = 60

# ── JSON parsing ──────────────────────────────────────────────────────────────

_TIME_FMTS = (
    "%Y-%m-%dT%H:%M:%S%z",  # nginx $time_iso8601: 2026-04-27T12:00:00+00:00
    "%Y-%m-%dT%H:%M:%S.%f%z",  # with microseconds
    "%d/%b/%Y:%H:%M:%S %z",  # nginx $time_local fallback
)


def _parse_time(raw: str) -> float:
    for fmt in _TIME_FMTS:
        try:
            return datetime.strptime(raw.strip(), fmt).timestamp()
        except ValueError:
            continue
    return time.time()


def _parse_line(line: str) -> dict | None:
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None

    # Field name matches nginx log_format json_hng: "source_ip"
    ip = obj.get("source_ip") or obj.get("remote_addr")
    if not ip:
        return None

    try:
        status = int(obj.get("status", 0))
    except (TypeError, ValueError):
        status = 0

    raw_time = (
        obj.get("timestamp") or obj.get("time_local") or obj.get("time_iso8601") or ""
    )
    ts = _parse_time(raw_time) if raw_time else time.time()

    return {
        "ip": ip,
        "ts": ts,
        "status": status,
        "method": obj.get("method", ""),
        "path": obj.get("path", ""),
        "response_size": obj.get("response_size", 0),
        "is_error": status >= 400,
    }


# ── Sliding-window ingestion


def _prune(d: deque, cutoff: float) -> None:
    while d and d[0] < cutoff:
        d.popleft()


def _prune_pairs(d: deque, cutoff: float) -> None:
    while d and d[0][0] < cutoff:
        d.popleft()


def ingest(entry: dict) -> None:
    ip, ts = entry["ip"], entry["ts"]
    cutoff = ts - WINDOW_SECONDS
    with state_lock:
        _prune_pairs(global_window, cutoff)
        global_window.append((ts, ip))

        if ip not in ip_windows:
            ip_windows[ip] = deque()
        _prune(ip_windows[ip], cutoff)
        ip_windows[ip].append(ts)

        if entry["is_error"]:
            _prune_pairs(global_error_window, cutoff)
            global_error_window.append((ts, ip))

            if ip not in ip_error_windows:
                ip_error_windows[ip] = deque()
            _prune(ip_error_windows[ip], cutoff)
            ip_error_windows[ip].append(ts)


# ── Persistent offset ───


def _offset_path(log_path: str) -> str:
    return log_path + ".offset"


def _load_offset(log_path: str) -> int:
    try:
        with open(_offset_path(log_path)) as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return 0


def _save_offset(log_path: str, offset: int) -> None:
    try:
        tmp = _offset_path(log_path) + ".tmp"
        with open(tmp, "w") as f:
            f.write(str(offset))
        os.replace(tmp, _offset_path(log_path))
    except OSError:
        pass


def _inode(path: str) -> int | None:
    try:
        return os.stat(path).st_ino
    except OSError:
        return None


# ── File handler ──


class _Handler(FileSystemEventHandler):
    def __init__(self, file_path: str) -> None:
        self._log_path = os.path.abspath(file_path)
        self._offset = _load_offset(file_path)
        self._inode = _inode(file_path)
        self._lock = threading.Lock()
        self._check_rotation()

    def on_modified(self, event) -> None:
        if os.path.abspath(event.src_path) == self._log_path:
            self._drain()

    def on_created(self, event) -> None:
        if os.path.abspath(event.src_path) == self._log_path:
            with self._lock:
                self._offset = 0
                self._inode = _inode(self._log_path)
                _save_offset(self._log_path, 0)
            self._drain()

    def on_deleted(self, event) -> None:
        if os.path.abspath(event.src_path) == self._log_path:
            with self._lock:
                self._offset = 0
                self._inode = None
                _save_offset(self._log_path, 0)

    def _check_rotation(self) -> None:
        current_inode = _inode(self._log_path)
        if current_inode is None:
            return
        if current_inode != self._inode:
            self._offset = 0
            self._inode = current_inode
            _save_offset(self._log_path, 0)
            return
        try:
            if os.path.getsize(self._log_path) < self._offset:
                self._offset = 0
                _save_offset(self._log_path, 0)
        except OSError:
            pass

    def _drain(self) -> None:
        with self._lock:
            self._check_rotation()
            try:
                with open(self._log_path, "r", errors="replace") as f:
                    f.seek(self._offset)
                    for line in f:
                        entry = _parse_line(line)
                        if entry:
                            ingest(entry)
                    new_offset = f.tell()
                self._offset = new_offset
                _save_offset(self._log_path, new_offset)
            except OSError:
                pass


# ── Public entry point ──


def start(file_path: str):
    handler = _Handler(file_path)
    watch_dir = os.path.dirname(os.path.abspath(file_path)) or "."
    observer = Observer()
    observer.schedule(handler, path=watch_dir, recursive=False)
    observer.start()
    return observer
