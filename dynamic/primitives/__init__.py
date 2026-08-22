#!/usr/bin/env python3
"""
primitives/ — the probe registry.

`dynamic/probe.py` keeps the original eight primitives and the CLI; everything added for live-website
coverage lives here, one module per group, registered through @primitive. `probe.PRIMITIVES` is the
union, so every existing name, signature and selftest behaviour is unchanged.

Two things every primitive here must honour, because a live target lies in ways a local fixture does
not:

  * BASELINES. An SPA answers HTTP 200 for every unknown path; a WAF answers instead of the app.
    A signal that matches the soft-404 fingerprint is not a signal. Take `ctx` and compare.
  * BENIGN AND BOUNDED. No destructive verbs, no availability testing, no proof that a bystander
    receives. Cache poisoning, cache deception, smuggling and takeover are detection-only — see
    the disclosure-ethics skill, which is binding and not optional reading.

A primitive that cannot answer safely returns confirmed=False with `blocked=True` in its evidence.
That surfaces as BLOCKED in the coverage matrix, never as CLEAR.
"""
from __future__ import annotations

import hashlib
import http.server
import json
import re
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "dynamic"))
sys.path.insert(0, str(ROOT / "static"))

from scope import http as requests  # noqa: E402  — the guard, never bare requests

TIMEOUT = 10


@dataclass
class ProbeResult:
    name: str
    confirmed: bool
    endpoint: str = ""
    payload: str = ""
    status: int = 0
    detail: str = ""
    evidence: dict = field(default_factory=dict)


def blocked(name: str, endpoint: str, why: str) -> ProbeResult:
    """The surface exists but could not be tested safely or within scope. Not a CLEAR."""
    return ProbeResult(name, False, endpoint, detail=f"BLOCKED: {why}",
                       evidence={"blocked": True, "reason": why})


# --------------------------------------------------------------------------- registry ---
REGISTRY: dict = {}
META: dict = {}


def primitive(name: str, default_param: str = "", group: str = "", cwe: str = "",
              needs: str = "", detection_only: bool = False):
    """Register a probe. `needs` names what the caller must supply beyond a base URL
    (e.g. "two identities", "an authenticated cookie") so the runner can report BLOCKED
    instead of silently under-testing."""
    def deco(fn):
        REGISTRY[name] = fn
        META[name] = {"group": group, "cwe": cwe, "default_param": default_param,
                      "needs": needs, "detection_only": detection_only,
                      "doc": (fn.__doc__ or "").strip().split("\n")[0]}
        return fn
    return deco


# -------------------------------------------------------------------------- baselines ---
def shape(body: str) -> str:
    """Structural fingerprint that survives dynamic content (ids, timestamps, CSRF tokens).
    Same function web/recon.py uses, so the values are comparable."""
    skel = re.sub(r"[0-9a-f]{8,}|\d+", "#", (body or "")[:4000])
    return hashlib.sha256(re.sub(r"\s+", " ", skel).encode("utf-8", "replace")).hexdigest()[:16]


class Ctx:
    """What a primitive needs to tell a real signal from the target's ambient noise."""

    def __init__(self, baselines: dict | None = None, identities: dict | None = None,
                 dialects: list | None = None, marker: str = "probe-9c2f", opts: dict | None = None):
        self.baselines = baselines or {}
        self.identities = identities or {}      # name -> Cookie header / bearer value
        self.dialects = dialects or []
        self.marker = marker
        self.opts = opts or {}

    def fresh_marker(self, tag: str = "") -> str:
        """A marker unique to THIS run.

        Write-then-read-back primitives (CSRF, mass assignment, second-order) confirm on "the value
        is present now and was absent before". A fixed marker makes the second run of a sweep report
        CLEAR on a target the first run already wrote to — the bug is still there, the probe just
        can't see it any more. Uniqueness per attempt is what keeps re-runs honest.
        """
        import random
        base = (self.marker or "probe-9c2f").rsplit("-", 1)[0]
        return f"{base}-{tag + '-' if tag else ''}{random.randrange(16**4):04x}"

    @classmethod
    def load(cls, slug: str, **kw) -> "Ctx":
        import _common as C
        b = C.workdir(slug) / "web" / "baselines.json"
        base = {}
        if b.exists():
            try:
                base = json.loads(b.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                base = {}
        fp = C.workdir(slug) / "web" / "fingerprint.json"
        dialects = []
        if fp.exists():
            try:
                dialects = json.loads(fp.read_text(encoding="utf-8")).get("ssti_dialects") or []
            except json.JSONDecodeError:
                pass
        return cls(baselines=base, dialects=dialects, **kw)

    # ---- the questions every primitive should ask before believing a response ----
    def is_soft_404(self, resp) -> bool:
        s = self.baselines.get("soft_404") or {}
        if not s:
            return False
        body = resp.text or ""
        if s.get("status") == resp.status_code and s.get("fingerprint") == shape(body):
            return True
        # length within 2% and same status is the usual SPA shell with a different route name
        return (s.get("status") == resp.status_code and s.get("length")
                and abs(len(body) - s["length"]) <= max(16, 0.02 * s["length"]))

    def differs_from_baseline(self, resp, which: str = "soft_404") -> bool:
        b = self.baselines.get(which) or {}
        if not b:
            return True                       # no baseline captured: caller must say so in the report
        return shape(resp.text or "") != b.get("fingerprint")

    def has_baselines(self) -> bool:
        return bool(self.baselines.get("soft_404"))


# ------------------------------------------------------------ out-of-band callback sink ---
class _Sink(http.server.BaseHTTPRequestHandler):
    hits: list = []

    def do_GET(self):  # noqa: N802
        _Sink.hits.append({"path": self.path, "headers": dict(self.headers)})
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")

    do_POST = do_GET

    def log_message(self, *a):
        return


def start_sink() -> tuple[str, http.server.HTTPServer]:
    """A local listener that proves a server-side fetch happened. Same idea as probe._start_sink;
    duplicated here so this package has no import cycle back into probe.py."""
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    srv = http.server.HTTPServer(("127.0.0.1", port), _Sink)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _Sink.hits = []
    return f"http://127.0.0.1:{port}/probe-{int(time.time())}", srv


def sink_hits() -> list:
    return list(_Sink.hits)


# ------------------------------------------------------------------------- HTTP helper ---
def send(method: str, url: str, ctx: Ctx | None = None, identity: str = "", **kw):
    """One request, with the identity's credential attached and a sane timeout."""
    kw.setdefault("timeout", TIMEOUT)
    headers = dict(kw.pop("headers", {}) or {})
    if identity and ctx and identity in ctx.identities:
        cred = ctx.identities[identity]
        headers["Cookie" if "=" in cred and "Bearer" not in cred else "Authorization"] = cred
    if headers:
        kw["headers"] = headers
    return requests.request(method.upper(), url, **kw)


def timed(method: str, url: str, **kw) -> tuple:
    t0 = time.monotonic()
    r = requests.request(method.upper(), url, timeout=kw.pop("timeout", TIMEOUT), **kw)
    return r, (time.monotonic() - t0)


def median(xs: list) -> float:
    xs = sorted(xs)
    n = len(xs)
    return xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2


# Importing the modules is what populates REGISTRY.
from . import injection, access, authn, websurface, apis  # noqa: E402,F401
