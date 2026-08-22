#!/usr/bin/env python3
"""
collect.py — assemble a reproducible evidence bundle for a confirmed finding.

Writes work/<slug>/evidence/<finding_id>/ with everything a maintainer needs to reproduce:
  request+response, server-log/stack-trace excerpt, environment + versions, target commit,
  timing, and the PoC command. (The same bundle can be assembled by hand — see poc-craft skill.)

  python evidence/collect.py <target> --finding <id> --poc "<cmd>" \
      [--request "<req>"] [--response "<resp>"] [--url <poc-url>] [--log <server.log>]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "static"))
import _common as C  # noqa: E402


def _sha256(p: Path) -> str:
    try:
        return "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest()
    except OSError:
        return ""


def slice_transcript(target: str, dest: Path, ids: list) -> dict:
    """Copy the cited exchanges out of work/<slug>/web/transcript.jsonl into the bundle.

    For a live-website finding these T##### ids are what the report cites in place of `file:line`,
    and `hunt validate-report` re-checks that the hashes here still match the transcript. Read the
    slice before shipping: response bodies can carry real user data, and the bundle leaves the
    machine.
    """
    src = C.workdir(target) / "web" / "transcript.jsonl"
    if not src.exists() or not ids:
        return {"found": [], "missing": list(ids), "source": str(src)}
    want, kept = set(ids), []
    for line in src.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("id") in want:
            kept.append(rec)
    (dest / "transcript.jsonl").write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in kept) + "\n", encoding="utf-8")
    found = [r["id"] for r in kept]
    return {"found": found, "missing": sorted(want - set(found)), "source": str(src)}


def collect(target: str, finding: str, poc: str, request: str = "", response: str = "",
            url: str = "", log: str = "", root_cause: str = "",
            transcript_ids: str = "", screenshot: str = "", har: str = "") -> Path:
    d = C.workdir(target) / "evidence" / finding
    d.mkdir(parents=True, exist_ok=True)

    tslice = {}
    if transcript_ids:
        ids = [i.strip() for i in transcript_ids.split(",") if i.strip()]
        tslice = slice_transcript(target, d, ids)
        if tslice.get("missing"):
            print(f"warn: transcript ids not found: {', '.join(tslice['missing'])}", file=sys.stderr)
    for label, path in (("screenshot", screenshot), ("har", har)):
        if path and Path(path).exists():
            import shutil
            shutil.copy2(path, d / Path(path).name)     # hashed automatically with the rest

    # live capture if a url was given
    if url and not response:
        try:
            import requests
            r = requests.get(url, timeout=8)
            request = request or f"GET {url}"
            response = f"HTTP {r.status_code}\n" + "\n".join(
                f"{k}: {v}" for k, v in r.headers.items()) + "\n\n" + r.text[:2000]
        except Exception as e:  # noqa: BLE001
            response = f"(capture failed: {e})"

    (d / "poc.txt").write_text(poc + "\n", encoding="utf-8")
    if request:
        (d / "request.txt").write_text(request, encoding="utf-8")
    if response:
        (d / "response.txt").write_text(response, encoding="utf-8")

    # server-log / stack-trace excerpt
    log_path = Path(log) if log else None
    if not log_path:
        cand = list((C.workdir(target)).rglob("server.log"))
        log_path = cand[0] if cand else None
    if log_path and log_path.exists():
        tail = log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-60:]
        (d / "server_log_excerpt.txt").write_text("\n".join(tail), encoding="utf-8")

    # environment + target commit
    src = Path(target)
    commit = ""
    if (src / ".git").exists():
        try:
            commit = subprocess.run(["git", "-C", str(src), "rev-parse", "HEAD"],
                                    capture_output=True, text=True).stdout.strip()
        except Exception:  # noqa: BLE001
            pass
    # root-cause graph: accept an inline string OR a path to a file (endpoint -> ... -> sink)
    rc_text = ""
    if root_cause:
        rc_path = Path(root_cause)
        rc_text = rc_path.read_text(encoding="utf-8", errors="replace") if rc_path.exists() else root_cause
        (d / "root_cause.md").write_text(rc_text, encoding="utf-8")

    # A live target has no commit, so pin what it does have: the origin, the scope that authorized
    # the test, and when it was observed (a live host can be patched between test and read).
    prof = {}
    pf = C.workdir(target) / "profile.json"
    if pf.exists():
        try:
            prof = json.loads(pf.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            prof = {}

    meta = {"finding_id": finding, "target": str(src), "commit": commit,
            "collected_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "target_kind": prof.get("kind", "src"),
            "target_url": prof.get("origin", ""),
            "scope_digest": prof.get("scope_digest", ""),
            "program": prof.get("program", {}),
            "test_window": prof.get("test_window", {}),
            "platform": platform.platform(), "python": platform.python_version()}
    (d / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    # reproducible manifest: every artifact + its sha256 so a maintainer can verify the bundle.
    def _f(name: str) -> dict | None:
        p = d / name
        return {"file": name, "sha256": _sha256(p)} if p.exists() else None

    log_excerpt = d / "server_log_excerpt.txt"
    log_txt = log_excerpt.read_text(encoding="utf-8", errors="replace") if log_excerpt.exists() else ""
    stack = [ln for ln in log_txt.splitlines()
             if any(k in ln.lower() for k in ("traceback", "error", "exception", ".py\", line"))]
    manifest = {
        "finding_id": finding, "target": str(src), "commit": commit,
        "collected_at": meta["collected_at"], "poc": poc,
        "requests": _f("request.txt"), "responses": _f("response.txt"),
        "logs": _f("server_log_excerpt.txt"), "stack_traces": stack[:40],
        "root_cause": _f("root_cause.md"),
        "target_kind": meta["target_kind"], "target_url": meta["target_url"],
        "scope_digest": meta["scope_digest"], "program": meta["program"],
        "test_window": meta["test_window"],
        "transcript": _f("transcript.jsonl"),
        "transcript_ids": tslice.get("found", []),
        "hashes": {f.name: _sha256(f) for f in sorted(d.iterdir()) if f.is_file()},
    }
    (d / "evidence.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(f"evidence bundle -> {d}")
    for f in sorted(d.iterdir()):
        print(f"  {f.name}")
    return d


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("target")
    ap.add_argument("--finding", required=True)
    ap.add_argument("--poc", required=True)
    ap.add_argument("--request", default="")
    ap.add_argument("--response", default="")
    ap.add_argument("--url", default="")
    ap.add_argument("--log", default="")
    ap.add_argument("--root-cause", default="", dest="root_cause",
                    help="root-cause graph text OR path to a file (endpoint -> ... -> sink)")
    ap.add_argument("--transcript-ids", default="", dest="transcript_ids",
                    help="T00203,T00287 — the exchanges that prove a live-website finding")
    ap.add_argument("--screenshot", default="", help="browser-confirmed classes: the rendered proof")
    ap.add_argument("--har", default="")
    args = ap.parse_args()
    collect(args.target, args.finding, args.poc, args.request, args.response, args.url,
            args.log, args.root_cause, args.transcript_ids, args.screenshot, args.har)
    return 0


if __name__ == "__main__":
    sys.exit(main())
