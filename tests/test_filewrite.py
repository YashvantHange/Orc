#!/usr/bin/env python3
"""
arbitrary_file_write: three outcomes, four containment mechanisms, and the safety properties.

TWO THINGS THESE TESTS EXIST TO PREVENT.

1. MECHANISM-LEVEL OVERFITTING. It is not enough that the probe passes on a `realpath()` fixture.
   The invariant is "no reliable containment", and basename reduction, an allowlist and a generated
   name are all containment. A probe that only recognises realpath() would teach the pipeline
   "no realpath == vulnerable", which is wrong in both directions. So there is one safe fixture per
   mechanism, and every one of them must come back not-confirmed.

2. A PROBE THAT DAMAGES A HOST. A write probe is the most dangerous thing in this pipeline: the
   payloads a real attacker uses (~/.ssh/authorized_keys, .bashrc, cron, a .pth) are exactly what we
   must never touch. Overwriting is an incident, not a test. That property gets tests, not a comment.
"""
from __future__ import annotations

import json
import os
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

ROOT = Path(__file__).resolve().parent.parent
for sub in ("web", "dynamic", "static"):
    sys.path.insert(0, str(ROOT / sub))

import primitives as P   # noqa: E402
import sweep             # noqa: E402
import verdict as V      # noqa: E402

STORE: dict = {}          # "written" files: path -> content
PREEXISTING = "/tmp/already-here.txt"


class App(BaseHTTPRequestHandler):
    """One write endpoint per containment mechanism, plus a read-back."""

    def _send(self, code, body, ctype="application/json"):
        raw = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except (ValueError, TypeError):
            return {}

    def do_POST(self):  # noqa: N802
        u = urlsplit(self.path)
        b = self._body()
        name = str(b.get("filename", ""))
        content = str(b.get("content", ""))

        if u.path == "/vuln/save":
            # No containment at all: the caller names the destination.
            STORE[_norm(name)] = content
            return self._send(200, json.dumps({"saved": name}))

        if u.path == "/safe-basename/save":
            STORE["/uploads/" + os.path.basename(_norm(name))] = content
            return self._send(200, json.dumps({"saved": "ok"}))

        if u.path == "/safe-realpath/save":
            dest = os.path.normpath(os.path.join("/uploads", _norm(name)))
            if not dest.startswith("/uploads/"):
                return self._send(400, json.dumps({"error": "outside root"}))
            STORE[dest] = content
            return self._send(200, json.dumps({"saved": "ok"}))

        if u.path == "/safe-allowlist/save":
            if _norm(name) not in ("/uploads/a.txt", "/uploads/b.txt"):
                return self._send(400, json.dumps({"error": "not an allowed destination"}))
            STORE[_norm(name)] = content
            return self._send(200, json.dumps({"saved": "ok"}))

        if u.path == "/safe-generated/save":
            STORE["/uploads/generated-0001.bin"] = content      # caller never names it
            return self._send(200, json.dumps({"saved": "ok"}))

        if u.path == "/ambiguous/save":
            # Errors on a traversal-shaped name and writes nothing. The classic false positive.
            if ".." in name or name.startswith("/"):
                return self._send(500, json.dumps({"error": "internal"}))
            STORE["/uploads/" + name] = content
            return self._send(200, json.dumps({"saved": "ok"}))

        return self._send(404, json.dumps({"error": "nope"}))

    def do_GET(self):  # noqa: N802
        u = urlsplit(self.path)
        q = parse_qs(u.query)

        if u.path == "/read-always-occupied":
            return self._send(200, "SOMETHING IS ALREADY HERE", "text/plain")

        if u.path == "/read":
            want = _norm((q.get("file") or [""])[0])
            if want in STORE:
                return self._send(200, STORE[want], "text/plain")
            return self._send(404, "not found", "text/plain")

        # the app serves whatever it stored, at its own path
        if _norm(u.path) in STORE:
            return self._send(200, STORE[_norm(u.path)], "text/plain")
        return self._send(404, "not found", "text/plain")

    def log_message(self, *a):
        return


def _norm(p: str) -> str:
    """Resolve traversal the way a naive filesystem would, so the fixture is actually vulnerable."""
    p = (p or "").replace("\\", "/")
    for enc, dec in (("%2e", "."), ("%2f", "/"), ("%252e", "."), ("%252f", "/")):
        p = p.replace(enc, dec).replace(enc.upper(), dec)
    while "....//" in p:
        p = p.replace("....//", "../")
    out = []
    for part in p.split("/"):
        if part == "..":
            if out:
                out.pop()
        elif part not in ("", "."):
            out.append(part)
    return "/" + "/".join(out)


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture()
def base():
    STORE.clear()
    STORE[PREEXISTING] = "PRE-EXISTING CONTENT DO NOT TOUCH"
    port = _free_port()
    srv = HTTPServer(("127.0.0.1", port), App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        srv.shutdown()


def run(base, endpoint, **opts):
    return P.REGISTRY["arbitrary_file_write"](base, endpoint, "filename", P.Ctx(opts=opts))


# ============================================================ outcome 1: it fires ===
def test_unsanitized_write_is_confirmed(base):
    r = run(base, "/vuln/save", readback="/read")
    assert sweep.verdict(r) == "HIT"
    assert r.evidence["write_confirmed"] is True
    assert r.evidence["write_attempted"] is True


def test_evidence_says_how_the_write_was_established(base):
    """A read-back is a dependency on another primitive; the bundle must not hide that."""
    r = run(base, "/vuln/save", readback="/read")
    assert r.evidence.get("readback_confirmed") is True
    assert "dependency of this evidence" in r.evidence["how"]
    assert V.write_confirmed(r.evidence)


# =================================== outcome 2: containment, one fixture per mechanism ===
@pytest.mark.parametrize("endpoint,mechanism", [
    ("/safe-basename/save", "basename reduction"),
    ("/safe-realpath/save", "canonical containment"),
    ("/safe-allowlist/save", "destination allowlist"),
    ("/safe-generated/save", "generated name"),
])
def test_every_containment_mechanism_is_respected(base, endpoint, mechanism):
    """The mechanism-overfitting guard: 'no realpath()' must not mean 'vulnerable'."""
    r = run(base, endpoint, readback="/read")
    assert sweep.verdict(r) != "HIT", (
        f"{mechanism} is valid containment, but the probe reported a write - it has learned a "
        f"mechanism instead of the invariant")


# ======================================= outcome 3: ambiguous is a LEAD, never a finding ===
def test_a_500_is_not_a_write(base):
    """The third outcome most probes omit, and the one that generates false reports."""
    r = run(base, "/ambiguous/save", readback="/read")
    assert sweep.verdict(r) != "HIT"
    assert r.evidence.get("lead") is True
    assert "not a write" in r.detail
    assert not V.write_confirmed(r.evidence)


def test_no_readback_is_blocked_not_cleared(base):
    """A write succeeds silently. Without an oracle the class is untested, not defended."""
    r = run(base, "/safe-basename/save")
    assert sweep.verdict(r) in ("BLOCKED", "NOT-CONFIRMED")
    assert sweep.verdict(r) != "CLEAR"


# ============================================================ safety: it cannot do harm ===
def test_a_pre_existing_file_is_never_overwritten(base):
    """Overwriting on a host we do not own is an incident, not a test.

    NOTE ON WHY THIS TEST LOOKS THE WAY IT DOES. An earlier version asserted only that a fixture
    file at a fixed path was unchanged - and it passed with the overwrite guard entirely deleted,
    because the probe never targets that path anyway. A safety test that cannot fail is worse than
    no test: it reads as assurance. The guard is now exercised directly, below.
    """
    before = STORE[PREEXISTING]
    run(base, "/vuln/save", readback="/read")
    assert STORE[PREEXISTING] == before


def test_the_overwrite_guard_actually_fires(base):
    """Every destination reads as occupied, so the probe must write nothing at all."""
    r = run(base, "/vuln/save", readback="/read-always-occupied")
    assert r.evidence.get("skipped_occupied"), (
        "the probe wrote without checking - the read-before-write guard did not fire")
    assert not r.evidence.get("artifacts_written"), (
        "the probe created files at destinations it had been told were occupied")
    assert sweep.verdict(r) != "HIT"


def test_the_forbidden_guard_actually_fires(base):
    """Aim the probe somewhere sensitive; it must refuse by name rather than comply."""
    r = run(base, "/vuln/save", readback="/read", dest_dir="root/.ssh")
    assert r.evidence.get("skipped_forbidden"), (
        "a sensitive destination was not refused - _is_forbidden is unreachable in the live path")
    assert not any(".ssh" in w for w in r.evidence.get("artifacts_written", []))


def test_artifacts_are_disclosed_on_every_outcome(base):
    """We cannot delete remotely, so the guarantee is disclosure - on hits and misses alike."""
    hit = run(base, "/vuln/save", readback="/read")
    assert hit.evidence["artifacts_written"], "a confirmed write disclosed no artifacts"
    assert "remove them" in hit.evidence["artifact_note"]

    lead = run(base, "/ambiguous/save", readback="/read")
    assert "artifact_note" in lead.evidence, "a LEAD must disclose artifacts too"


def test_sensitive_destinations_are_refused_by_name():
    """Refused whatever the caller passes - the finding never requires touching these."""
    from primitives import filewrite as FW
    for bad in ("/root/.ssh/authorized_keys", "../../../home/u/.bashrc",
                "/etc/cron.d/evil", "/usr/lib/python3/site-packages/x.pth", "/app/.env"):
        assert FW._is_forbidden(bad), f"{bad} must be refused"
    assert not FW._is_forbidden("/tmp/hunt-probe-9c2f.txt")


def test_the_marker_is_unique_per_run(base):
    """A fixed marker makes a second run report CLEAR on a target the first run already wrote to."""
    a = run(base, "/vuln/save", readback="/read")
    STORE.clear()
    STORE[PREEXISTING] = "x"
    b = run(base, "/vuln/save", readback="/read")
    assert a.evidence["marker"] != b.evidence["marker"]


def test_execution_is_scored_never_performed(base):
    """Reaching the location is the finding; running what we wrote is forbidden."""
    r = run(base, "/vuln/save", readback="/read")
    assert "execution_tested" not in r.evidence
    # and the scoring path works when the destination is executable ground
    from primitives import filewrite as FW
    assert "import path" in FW._execution_hint("/usr/lib/python3.11/site-packages/x.pth")
    assert FW._execution_hint("/tmp/plain.txt") == ""


# ==================================================================== wiring ===
def test_registered_and_targeted():
    assert "arbitrary_file_write" in P.REGISTRY
    assert "arbitrary_file_write" in sweep.TARGETING


def test_the_uncovered_rows_are_now_covered():
    sys.path.insert(0, str(ROOT / "tools"))
    import audit_coverage
    uncovered = {f["class"] for f in audit_coverage.audit()["uncovered"]}
    assert "Arbitrary file WRITE" not in uncovered
    assert "Write-then-execute chain (write reaches an executed path)" not in uncovered
