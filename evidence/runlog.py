#!/usr/bin/env python3
"""
runlog.py — record what a PoC ACTUALLY did, so a report can be checked against reality.

This module makes exactly one claim and makes it honestly: the bytes in `runlog.json` came out of a
process that really ran on this machine. It records; it never judges. Whether the finding is real,
whether the prose is good, whether the CVSS is right — none of that is decided here. Agents decide
that (see the report-auditor / report-editor agents). A script that judged those would produce false
positives, which is worse than no check at all.

Why it exists: `collect.py` writes `poc.txt` from a *string an agent passes in*, so a bundle proves
only that somebody typed a command. Nothing proved it ran, and nothing tied the "Observed output" in
a report to a real process. That is the gap this closes.

  python evidence/runlog.py <target> <finding-id> --cmd "python poc.py" [--cwd DIR]
      [--python /path/to/venv/python] [--volatile 'run=[0-9a-f]{32}'] [--timeout 600]

Each invocation APPENDS one entry to work/<slug>/evidence/<finding-id>/runlog.json. The delivery gate
wants at least two, because "I ran it twice and got the same thing" is the cheapest defence against a
one-off fluke.

On forgery, plainly: a self-consistent runlog can be hand-written by someone determined to fake one —
the hashes are over content, not signed by a key we could keep secret from the thing writing the file.
What this buys is that fabrication stops being something that can happen by *inattention*. An agent
can no longer drift from "I think the output looked like this" into a shipped report; it would have to
deliberately construct a fake process record, with a plausible freeze, commit, timings and exit code.
That is a bright line, and the auditors read the output for plausibility on top of it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "static"))
import _common as C  # noqa: E402

SCHEMA = 1
MIN_RUNS = 2                    # the delivery gate's "run it at least twice"


def _h(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def runlog_path(target: str, finding: str) -> Path:
    d = C.workdir(target) / "evidence" / finding
    d.mkdir(parents=True, exist_ok=True)
    return d / "runlog.json"


def load(target: str, finding: str) -> dict:
    p = runlog_path(target, finding)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


# ------------------------------------------------------------------- environment capture ---
def _freeze(python: str) -> str:
    """`pip freeze` from the interpreter the PoC actually used.

    The interpreter matters: a PoC usually builds its own venv, so freezing OUR venv would record
    versions the reader can never reproduce. --python is how the caller points at the right one.
    """
    try:
        p = subprocess.run([python, "-m", "pip", "freeze"],
                           capture_output=True, text=True, timeout=180)
        return p.stdout or ""
    except Exception as e:                                  # noqa: BLE001
        return f"(pip freeze failed: {e})"


def _py_version(python: str) -> str:
    if os.path.abspath(python) == os.path.abspath(sys.executable):
        return sys.version.split()[0]
    try:
        p = subprocess.run([python, "-c", "import sys;print(sys.version.split()[0])"],
                           capture_output=True, text=True, timeout=60)
        return (p.stdout or "").strip()
    except Exception:                                       # noqa: BLE001
        return ""


def _git(target: str) -> dict:
    """Pin the target's commit, and say plainly whether the tree was dirty.

    A dirty tree means the reader cannot get back to what was tested, so the gate treats it as a
    failure rather than a warning — a report pinned to a commit that does not describe the bytes you
    ran is a report that will not reproduce.
    """
    src = Path(target)
    if not (src / ".git").exists():
        return {"commit": "", "tree_dirty": False, "is_git": False}
    def g(*args: str) -> str:
        try:
            p = subprocess.run(["git", "-C", str(src), *args],
                               capture_output=True, text=True, timeout=60)
            return (p.stdout or "").strip()
        except Exception:                                   # noqa: BLE001
            return ""
    return {"commit": g("rev-parse", "HEAD"),
            "branch": g("rev-parse", "--abbrev-ref", "HEAD"),
            "tree_dirty": bool(g("status", "--porcelain")),
            "is_git": True}


# ------------------------------------------------------------------------------ recording ---
def record(target: str, finding: str, cmd: str, cwd: str = "", python: str = "",
           volatile: list | None = None, timeout: int = 600, shell: bool = True) -> dict:
    """Run `cmd`, capture everything about it, append the entry, return it."""
    python = python or sys.executable
    volatile = [v for v in (volatile or []) if v.strip()]
    for v in volatile:                                      # fail fast on a bad regex
        re.compile(v)

    workdir = str(Path(cwd).resolve()) if cwd else os.getcwd()
    argv = cmd if shell else shlex.split(cmd, posix=not C.IS_WINDOWS)

    started, t0 = _now(), time.perf_counter()
    try:
        p = subprocess.run(argv, shell=shell, cwd=workdir, capture_output=True,
                           text=True, timeout=timeout)
        out, err, code, timed_out = p.stdout or "", p.stderr or "", p.returncode, False
    except subprocess.TimeoutExpired as e:
        out = e.stdout.decode("utf-8", "replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        err = e.stderr.decode("utf-8", "replace") if isinstance(e.stderr, bytes) else (e.stderr or "")
        code, timed_out = -1, True
    dur = round(time.perf_counter() - t0, 3)

    freeze = _freeze(python)
    entry = {
        "cmd": cmd,
        "argv": argv if isinstance(argv, list) else [argv],
        "shell": shell,
        "cwd": workdir,
        "started_at": started,
        "ended_at": _now(),
        "duration_s": dur,
        "timed_out": timed_out,
        "exit_code": code,
        "stdout": out,
        "stderr": err,
        "stdout_sha256": _h(out),
        "stderr_sha256": _h(err),
        "freeze": freeze,
        "freeze_sha256": _h(freeze),
        "python": python,
        "python_version": _py_version(python),
        "platform": platform.platform(),
        "target": str(target),
        "git": _git(target),
        "volatile": volatile,
    }

    doc = load(target, finding) or {"schema": SCHEMA, "finding_id": finding,
                                    "target": str(target), "runs": []}
    doc.setdefault("runs", []).append(entry)
    doc["updated_at"] = entry["ended_at"]
    runlog_path(target, finding).write_text(
        json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
    return entry


# --------------------------------------------------------------------------- verification ---
def verify(doc: dict) -> tuple[bool, list]:
    """Is this runlog internally consistent with something that really ran?

    Deterministic checks only. Every one of these is a fact about the file, not an opinion about the
    finding.
    """
    problems: list = []
    runs = (doc or {}).get("runs") or []
    if not runs:
        return False, ["no runs recorded — the PoC was never executed through `hunt poc-run`"]
    if len(runs) < MIN_RUNS:
        problems.append(f"only {len(runs)} recorded run(s); the delivery gate wants {MIN_RUNS} "
                        f"(re-run the PoC so a one-off fluke is ruled out)")
    for i, r in enumerate(runs):
        w = f"run[{i}]"
        if "exit_code" not in r:
            problems.append(f"{w}: no exit_code - this entry was not produced by poc-run")
        if r.get("timed_out"):
            problems.append(f"{w}: timed out after {r.get('duration_s')}s; output is partial")
        for stream in ("stdout", "stderr"):
            got, claimed = r.get(stream), r.get(f"{stream}_sha256")
            if got is None or not claimed:
                problems.append(f"{w}: {stream} or its hash is missing")
            elif _h(got) != claimed:
                problems.append(f"{w}: {stream}_sha256 does not match {stream} — the runlog was "
                                f"edited after the run")
        fz = r.get("freeze") or ""
        if not fz.strip():
            problems.append(f"{w}: no pip freeze captured")
        elif not re.search(r"(?m)^[A-Za-z0-9._-]+\s*==\s*\S+", fz) and "failed" not in fz:
            problems.append(f"{w}: freeze does not look like pip output")
        if r.get("freeze_sha256") and _h(fz) != r["freeze_sha256"]:
            problems.append(f"{w}: freeze_sha256 does not match freeze — edited after the run")
        g = r.get("git") or {}
        if g.get("is_git") and g.get("tree_dirty"):
            problems.append(f"{w}: target tree was dirty at run time — the pinned commit "
                            f"{g.get('commit', '')[:12]} does not describe what actually ran")
    return not problems, problems


def mask(text: str, patterns: list) -> str:
    """Blank out the values that legitimately change between runs (uuids, ports, timestamps).

    The patterns are the ones RECORDED in the runlog at capture time, never invented at compare time.
    That ordering is the point: you declare what is allowed to vary before you see whether the
    comparison passes, so the mask cannot be widened afterwards to make a mismatch disappear.
    """
    out = text
    for p in patterns or []:
        try:
            out = re.sub(p, "█", out)
        except re.error:
            continue
    return out


def find_output(doc: dict, needle: str) -> tuple[bool, str]:
    """Does `needle` appear verbatim in some recorded stdout/stderr? Returns (found, which run)."""
    norm = lambda s: s.replace("\r\n", "\n").strip()        # noqa: E731
    for i, r in enumerate(doc.get("runs") or []):
        pats = r.get("volatile") or []
        hay = mask(norm(r.get("stdout", "") + "\n" + r.get("stderr", "")), pats)
        if mask(norm(needle), pats) in hay:
            return True, f"run[{i}] {r.get('started_at', '')}"
    return False, ""


def freeze_has(doc: dict, package: str, version: str) -> tuple[bool, str]:
    """Was `package==version` really installed in the interpreter that ran the PoC?

    This is what catches a pinned version that does not exist — the report says `requests==2.34.2`,
    no recorded freeze mentions it, and the claim dies before a maintainer wastes an hour on it.
    """
    want = re.compile(rf"(?mi)^{re.escape(package)}\s*==\s*{re.escape(version)}\s*$")
    for i, r in enumerate(doc.get("runs") or []):
        if want.search(r.get("freeze", "")):
            return True, f"run[{i}]"
    return False, ""


def main() -> int:
    ap = argparse.ArgumentParser(description="record a real PoC execution")
    ap.add_argument("target", help="the target dir / repo slug the finding belongs to")
    ap.add_argument("finding", help="finding id, e.g. F018")
    ap.add_argument("--cmd", required=True, help="the exact command the report tells a maintainer to run")
    ap.add_argument("--cwd", default="", help="run it here (default: current directory)")
    ap.add_argument("--python", default="", help="the interpreter the PoC uses; pip freeze comes from it")
    ap.add_argument("--volatile", action="append", default=[],
                    help="regex for a value that legitimately changes between runs (repeatable)")
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--no-shell", action="store_true", help="exec argv directly instead of via a shell")
    a = ap.parse_args()

    e = record(a.target, a.finding, a.cmd, cwd=a.cwd, python=a.python,
               volatile=a.volatile, timeout=a.timeout, shell=not a.no_shell)
    doc = load(a.target, a.finding)
    n = len(doc.get("runs", []))
    print(f"recorded run #{n} - exit {e['exit_code']} in {e['duration_s']}s")
    print(f"  {runlog_path(a.target, a.finding)}")
    if e["stdout"]:
        head = e["stdout"].strip().splitlines()[:8]
        print("  stdout:")
        for ln in head:
            print(f"    {ln}")
        extra = len(e["stdout"].strip().splitlines()) - len(head)
        if extra > 0:
            print(f"    ... +{extra} more line(s)")
    if e["exit_code"] != 0:
        print(f"  note: non-zero exit. That is fine if the PoC is SUPPOSED to fail (a crash is often "
              f"the bug) — say so in the report.")
    ok, problems = verify(doc)
    if not ok:
        print("\n  not yet gate-ready:")
        for p in problems:
            print(f"    - {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
