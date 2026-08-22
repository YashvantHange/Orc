#!/usr/bin/env python3
"""
instrument.py — launch a target locally and instrument it for evidence.

Provides TargetProcess: builds an isolated env (venv for python / npm install for node),
launches the server on a chosen port, healthchecks it, and captures the strong evidence a
credible report needs: server stdout/stderr logs, uncaught stack traces, and per-request
timing (probes read the log for tracebacks after triggering a bug).

LOCAL BY CONSTRUCTION: this launches software you cloned yourself on 127.0.0.1. A live third-party
host is never launched — it is reached with `--url` plus a `scope.yml` (see dynamic/scope.py).
Never point probes at
a third-party host.
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IS_WINDOWS = sys.platform.startswith("win")


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _venv_python(venv: Path) -> Path:
    return venv / ("Scripts" if IS_WINDOWS else "bin") / ("python.exe" if IS_WINDOWS else "python")


class TargetProcess:
    """Context manager that launches, healthchecks, and tears down a local target."""

    def __init__(self, target: str, port: int | None = None, entry: str | None = None,
                 log_dir: Path | None = None):
        self.src = Path(target).resolve()
        self.port = port or free_port()
        self.entry = entry
        self.proc: subprocess.Popen | None = None
        self.log_dir = log_dir or (self.src.parent / "_dyn_logs")
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.log_dir / "server.log"
        self._log_fh = None
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.kind = self._detect_kind()

    def _detect_kind(self) -> str:
        if (self.src / "package.json").exists():
            return "node"
        if any(self.src.glob("*.py")):
            return "python"
        return "unknown"

    # -------------------------------------------------------------- setup + launch ---
    def _prepare_python(self) -> list[str]:
        venv = self.src / ".dynvenv"
        py = _venv_python(venv)
        if not py.exists():
            subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True,
                           capture_output=True)
            reqs = self.src / "requirements.txt"
            if reqs.exists():
                subprocess.run([str(py), "-m", "pip", "install", "-q", "-r", str(reqs)],
                               capture_output=True, timeout=1200)
        entry = self.entry or next((c for c in ("app.py", "main.py", "server.py", "run.py")
                                    if (self.src / c).exists()), None)
        if not entry:
            raise RuntimeError("no python entrypoint found (pass --entry)")
        return [str(py), entry]

    def _prepare_node(self) -> list[str]:
        npm = "npm.cmd" if IS_WINDOWS else "npm"
        if not (self.src / "node_modules").exists():
            subprocess.run([npm, "install", "--silent"], cwd=str(self.src),
                           capture_output=True, timeout=1200)
        entry = self.entry or "server.js"
        node = "node"
        if (self.src / entry).exists():
            return [node, entry]
        return [npm, "start"]

    def start(self) -> "TargetProcess":
        cmd = self._prepare_python() if self.kind == "python" else self._prepare_node()
        env = dict(os.environ, PORT=str(self.port))
        self._log_fh = open(self.log_path, "w", encoding="utf-8", errors="replace")
        kwargs = {}
        if IS_WINDOWS:
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        self.proc = subprocess.Popen(cmd, cwd=str(self.src), env=env,
                                     stdout=self._log_fh, stderr=subprocess.STDOUT, **kwargs)
        self._await_health()
        return self

    def _await_health(self, timeout: float = 40.0) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc and self.proc.poll() is not None:
                raise RuntimeError(f"target exited early (see {self.log_path})")
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=1):
                    time.sleep(0.5)  # let the framework finish binding routes
                    return
            except OSError:
                time.sleep(0.4)
        raise TimeoutError(f"target did not open :{self.port} within {timeout}s "
                           f"(see {self.log_path})")

    # -------------------------------------------------------------------- teardown ---
    def read_log(self) -> str:
        try:
            return self.log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def stop(self) -> None:
        if not self.proc:
            return
        try:
            if IS_WINDOWS:
                subprocess.run(["taskkill", "/PID", str(self.proc.pid), "/T", "/F"],
                               capture_output=True)
            else:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
        finally:
            if self._log_fh:
                self._log_fh.close()

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="launch + healthcheck a target, then hold it")
    ap.add_argument("target")
    ap.add_argument("--entry")
    ap.add_argument("--port", type=int)
    ap.add_argument("--seconds", type=int, default=8, help="how long to hold it up")
    a = ap.parse_args()
    with TargetProcess(a.target, a.port, a.entry) as t:
        print(f"up: {t.base_url}  (kind={t.kind}, log={t.log_path})")
        time.sleep(a.seconds)
    print("stopped")
