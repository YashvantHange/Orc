#!/usr/bin/env python3
"""
Acceptance test for the live-website path — boots work/_selftest/web_app, runs recon + the full
primitive sweep against 127.0.0.1, and asserts BOTH halves of the bar:

  * the seeded bugs are found            (detection)
  * the /api/safe/* twins and the 200-soft-404 produce ZERO hits   (false-positive rate)

The second half is the one that decides whether this is safe to point at a real bug-bounty program.
A sweep that "confirms" twenty classes on correctly-defended routes is worse than no sweep: it burns
the researcher's standing with the program.

  .venv/Scripts/python.exe tests/test_web_acceptance.py
  .venv/Scripts/python.exe -m pytest tests/test_web_acceptance.py -q

Skips (does not fail) when flask isn't importable by any interpreter we can find.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "static"))

FIXTURE = ROOT / "work" / "_selftest" / "web_app"
SCOPE = FIXTURE / "scope.yml"
PORT = int(os.environ.get("WEB_ACCEPTANCE_PORT", "8031"))
BASE = f"http://127.0.0.1:{PORT}"

# The full sweep against a fixture that exercises every class is slow, and most of it is not HTTP:
# measured at ~13.6k requests (328s on the wire) plus a browser launch for each of the six
# client-side classes. The old 900s was set when this fixture did not exist, and with one in place
# it killed the probe mid-run and reported the result as a detection failure - a stopwatch, not a
# finding. Override with WEB_ACCEPTANCE_PROBE_TIMEOUT when running on slower hardware.
PROBE_TIMEOUT = int(os.environ.get("WEB_ACCEPTANCE_PROBE_TIMEOUT", "2400"))

# Seeded classes the sweep is expected to catch. Kept deliberately short of the full HIT list so a
# harmless heuristic change doesn't fail the build — these are the ones that must never regress.
MUST_FIND = {
    "sqli_error", "sqli_boolean", "ssti", "nosqli", "xxe", "proto_pollution_server",
    "open_redirect", "upload_bypass", "idor_enum", "bfla_matrix", "mass_assignment",
    "method_override", "csrf", "clickjacking_header", "session_fixation", "host_header",
    "pwreset_token", "graphql_introspection", "cache_deception",
}
# Browser-only classes. Asserted separately: with no Chromium these must report NEEDS-BROWSER
# (never CLEAR), so their absence from the HIT set is only a failure when a browser is available.
MUST_FIND_BROWSER = {
    "dom_xss", "clickjacking", "postmessage_origin", "proto_pollution_client",
    "cookie_flags_effective", "csp_effective",
}
# Routes that are correctly defended. A HIT on any of them is a false positive, full stop.
SAFE_MARKERS = ("/api/safe/",)


def _python_with_flask() -> str | None:
    for cand in (FIXTURE / ".dynvenv" / "Scripts" / "python.exe",
                 ROOT / "work" / "_selftest" / "py_app" / ".dynvenv" / "Scripts" / "python.exe",
                 FIXTURE / ".dynvenv" / "bin" / "python",
                 Path(sys.executable)):
        if not cand.exists():
            continue
        try:
            r = subprocess.run([str(cand), "-c", "import flask"], capture_output=True, timeout=30)
            if r.returncode == 0:
                return str(cand)
        except (OSError, subprocess.SubprocessError):
            continue
    return None


def _port_holder(port: int) -> str:
    """Who already owns the port? Without this, a stale fixture and a broken one look identical."""
    try:
        out = subprocess.run(["netstat", "-ano"], capture_output=True, text=True,
                             timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return "(could not inspect the port)"
    pids = {line.split()[-1] for line in out.splitlines()
            if f":{port} " in line and "LISTEN" in line.upper()}
    if not pids:
        return "Nothing is listening there, so the fixture itself failed to start."
    return (f"PID(s) {', '.join(sorted(pids))} are already listening - most likely a fixture left "
            f"over from an earlier run. Kill them and retry.")


def _wait_up(timeout: float = 25.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            urllib.request.urlopen(BASE + "/", timeout=2).read()
            return True
        except (urllib.error.URLError, OSError):
            time.sleep(0.4)
    return False


def _login(user: str, pw: str) -> str:
    req = urllib.request.Request(
        BASE + "/api/login", method="POST",
        data=json.dumps({"username": user, "password": pw}).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        sc = r.headers.get("Set-Cookie", "")
    return sc.split(";")[0]


def run_acceptance() -> dict:
    py = _python_with_flask()
    if not py:
        raise RuntimeError("SKIP: no interpreter with flask available for the fixture")

    env = {**os.environ, "PORT": str(PORT), "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}
    proc = subprocess.Popen([py, str(FIXTURE / "app.py")], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not _wait_up():
            raise RuntimeError(f"fixture did not come up on port {PORT}. "
                               f"{_port_holder(PORT)} "
                               f"Set WEB_ACCEPTANCE_PORT to use a different port.")
        owner, other = _login("alice", "alice-pw"), _login("bob", "bob-pw")
        hunt = [sys.executable, str(ROOT / "hunt.py")]
        slug = f"_acceptance_{PORT}"

        subprocess.run(hunt + ["web", "recon", BASE, "--scope", str(SCOPE),
                               "--auth-cookie", owner, "--posture-path", "/account"],
                       cwd=ROOT, env=env, capture_output=True, timeout=600)
        subprocess.run(hunt + ["web", "probe", BASE, "--scope", str(SCOPE),
                               "--identity", f"owner={owner}", "--identity", f"other={other}",
                               "--opt", "ids=1,2", "--opt", "owner_marker=marker-A-9c2f",
                               "--opt", "readback=/api/profile",
                               "--opt", "emails=probe@example.invalid",
                               "--opt", "username=alice", "--opt", "password=alice-pw",
                               "--opt", "login=/api/login", "--opt", "victim_id=1", "--fast"],
                       cwd=ROOT, env=env, capture_output=True, timeout=PROBE_TIMEOUT)

        import _common as C
        sweep = C.workdir(BASE) / "web" / "sweep.json"
        if not sweep.exists():
            raise RuntimeError(f"no sweep.json at {sweep}")
        return json.loads(sweep.read_text(encoding="utf-8"))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


_CACHE: dict = {}


def _sweep() -> dict:
    """Run the acceptance sweep once per session - including when it FAILS.

    Caching only success meant a single failure was retried by every test in this file, and each
    retry launched another Flask app. Six relaunches against an already-occupied port leave six
    orphans, which then look like concurrent test runs. The failure is cached and re-raised so the
    first real error is the one every test reports.
    """
    if "err" in _CACHE:
        raise _CACHE["err"]
    if "d" not in _CACHE:
        try:
            _CACHE["d"] = run_acceptance()
        except BaseException as e:        # noqa: BLE001 - re-raised below, never swallowed
            _CACHE["err"] = e
            raise
    return _CACHE["d"]


def test_no_false_positives_on_defended_routes():
    """The half that matters most: correctly-defended twins must produce zero hits."""
    d = _sweep()
    fps = [r for r in d["results"] if r["verdict"] == "HIT"
           and any(m in (r.get("endpoint") or "") for m in SAFE_MARKERS)]
    assert not fps, ("primitives fired on deliberately-defended routes — this is the failure mode "
                     f"that burns a bug-bounty program: {[(r['name'], r['endpoint']) for r in fps]}")


def test_seeded_classes_are_found():
    d = _sweep()
    hits = {r["name"] for r in d["results"] if r["verdict"] == "HIT"}
    missing = MUST_FIND - hits
    assert not missing, f"seeded vulnerability classes no longer detected: {sorted(missing)}"


def test_browser_classes_found_or_honestly_degraded():
    """With Chromium: every browser class confirms. Without it: NEEDS-BROWSER, never CLEAR."""
    d = _sweep()
    by_name = {r["name"]: r for r in d["results"]}
    for name in MUST_FIND_BROWSER:
        r = by_name.get(name)
        assert r is not None, f"{name} did not run at all"
        assert r["verdict"] in ("HIT", "NEEDS-BROWSER"), (
            f"{name} reported {r['verdict']} — a browser class must confirm or declare itself "
            f"unrunnable; silently clearing it hides the whole client-side group")


def test_baselines_were_loaded():
    """Without baselines every verdict is untrustworthy on a soft-404 target — and the fixture
    deliberately returns HTTP 200 for unknown paths."""
    assert _sweep().get("baselines_loaded"), "sweep ran without recon baselines"


def test_blocked_is_reported_not_laundered():
    """A class that could not be tested must surface as BLOCKED, never as clear."""
    d = _sweep()
    blocked = [r for r in d["results"] if r["verdict"] == "BLOCKED"]
    assert blocked, "expected some BLOCKED verdicts (jwt/* need a token, --fast skips timing probes)"
    for r in blocked:
        assert r["detail"].startswith("BLOCKED:"), f"{r['name']} lost its blocked reason"


def test_manual_rows_are_listed():
    """Rows no primitive can settle must stay visible, with the recipe that closes them."""
    rows = _sweep().get("manual_rows") or {}
    assert len(rows) >= 10, "the manual/browser row list disappeared — classes would be silently unswept"
    for name, meta in rows.items():
        assert meta.get("recipe"), f"{name} has no recipe pointer"
        assert meta.get("kind") in ("MANUAL", "NEEDS-BROWSER")


def _run_all() -> int:
    try:
        _sweep()
    except RuntimeError as e:
        print(f"  {e}")
        return 0
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"  PASS {fn.__name__}")
        except Exception as e:                            # noqa: BLE001
            failed += 1
            print(f"  FAIL {fn.__name__}: {e}")
    d = _CACHE.get("d", {})
    print(f"\n  summary: {d.get('summary')}")
    print(f"{len(fns) - failed}/{len(fns)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run_all())
