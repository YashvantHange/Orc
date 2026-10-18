#!/usr/bin/env python3
"""
mitm_gate.py - a mitmproxy addon that puts external tools behind the same scope guard.

    mitmdump -q -p <port> -s dynamic/mitm_gate.py
        HUNT_SCOPE_FILE=work/<slug>/scope.yml
        HUNT_SLUG=<slug>
        HUNT_EXT_TOOL=sqlmap

WHY: `guardrails` Known gap #1 says a hand-rolled request skips dynamic/scope.py entirely - no
host/window/rate check and no T##### transcript entry, so the request is both unauthorized by
machinery and unciteable as evidence. Every external binary (sqlmap, ffuf, nuclei, dalfox, commix)
is a hand-rolled request by that definition. Routing them through this proxy closes the gap rather
than widening it: the tool can ignore its own flags, but it cannot ignore the proxy it is speaking
through.

THIS FILE HOLDS NO POLICY. It is a translator from a mitmproxy flow to a Scope call, and every
authorization decision, the rate bucket, the request budget, the required headers and the redaction
rules come from dynamic/scope.py. That is deliberate and it is the design constraint: two enforcement
paths that each implement the rules would drift, and the drift would be a security hole rather than a
cosmetic inconsistency.

REVIEW RULE: an `if` in this file that DECIDES authorization rather than delegating it is a defect.
The only conditionals below are about flow plumbing.
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "dynamic"))
sys.path.insert(0, str(ROOT / "static"))

import scope as S  # noqa: E402


class ScopeGate:
    """One instance per mitmdump process. Fails closed: if the scope will not load, nothing passes."""

    def __init__(self) -> None:
        self.tool = os.environ.get("HUNT_EXT_TOOL", "ext")
        self.slug = os.environ.get("HUNT_SLUG", "")
        self.primitive = f"ext:{self.tool}"
        self.broken = ""
        self.scope = None
        self.transcript = None

        path = os.environ.get("HUNT_SCOPE_FILE", "")
        if not path:
            self.broken = "HUNT_SCOPE_FILE is not set"
            return
        try:
            self.scope = S.Scope.load(path)
        except (S.ScopeError, OSError) as e:
            # Fail closed. A proxy that waves traffic through because it could not read its own
            # scope file is worse than no proxy: the tool believes it is being supervised.
            self.broken = f"{type(e).__name__}: {e}"
            return

        workdir = _workdir(self.slug)
        self.scope.attach_shared(workdir / "web" / "limits.json")
        self.transcript = S._Transcript(workdir / "web" / "transcript.jsonl", shared=True)

    # ------------------------------------------------------------------ mitmproxy hooks ---
    def request(self, flow) -> None:
        method = flow.request.method
        url = flow.request.pretty_url

        if self.broken:
            self._kill(flow, None, method, url,
                       f"scope gate inoperative ({self.broken})", "gate.fail_closed")
            return

        tid = self.transcript.next_id()
        flow.metadata["hunt_tid"] = tid
        flow.metadata["hunt_t0"] = time.monotonic()

        # Authorization. Scope decides; this file only reports what it decided.
        try:
            self.scope.check(method, url)
        except S.ScopeViolation as v:
            self._kill(flow, tid, method, url, v.reason, v.rule)
            return

        # Rate and budget, drawn from the same file the in-house path draws from, so one scope means
        # one budget however many processes are testing.
        try:
            flow.metadata["hunt_wait"] = self.scope.acquire(method, url)
        except S.ScopeViolation as v:
            self._kill(flow, tid, method, url, v.reason, v.rule)
            return

        # Concurrency. rps and max_requests were already shared with the in-house path above; the
        # SLOT was not, so an external tool proxied through here was rate-limited and budget-limited
        # but free to open as many simultaneous connections as it liked. sqlmap and ffuf are
        # threaded by default, so that is the same over-concurrency the shared limiter exists to
        # prevent, arriving through a different door. Held across the exchange, released on BOTH
        # the response and the error hook.
        flow.metadata["hunt_lease"] = self.scope.acquire_slot()

        # Policy-mandated attribution headers, applied here because a tool has no way to set them.
        for k, v in self.scope.required_headers.items():
            flow.request.headers[k] = v

    def response(self, flow) -> None:
        # Release before any early return below. A refusal never took a slot, but a flow that did
        # must not lose its release to a `return`.
        self.scope.release_slot(flow.metadata.pop("hunt_lease", ""))
        # A refusal sets flow.response itself, which makes mitmproxy call this hook as well. The
        # refusal record is already written, and writing a second record under the same T##### would
        # make the evidence citation ambiguous - the exact failure shared ids exist to prevent.
        if self.broken or "hunt_tid" not in flow.metadata or flow.metadata.get("hunt_refused"):
            return
        t0 = flow.metadata.get("hunt_t0") or time.monotonic()
        req_body = _text(flow.request.content)
        resp_body = _text(flow.response.content)
        self.transcript.write({
            "id": flow.metadata["hunt_tid"], "ts": S._now(), "identity": "ext",
            "primitive": self.primitive, "tool": self.tool, "finding": "",
            "method": flow.request.method, "url": flow.request.pretty_url,
            "req_headers": S._redact_headers(dict(flow.request.headers)),
            "req_body": S._truncate(S._redact_body(req_body), S._MAX_REQ_BODY),
            "req_body_sha256": S._sha(req_body),
            "status": flow.response.status_code,
            "resp_headers": S._redact_headers(dict(flow.response.headers)),
            "resp_body": S._truncate(resp_body, S._MAX_RESP_BODY),
            "resp_body_sha256": S._sha(resp_body),
            "elapsed_ms": round((time.monotonic() - t0) * 1000.0, 1),
            "rate_wait_ms": round(float(flow.metadata.get("hunt_wait") or 0.0) * 1000, 1),
            "scope_digest": self.scope.digest()})

    def error(self, flow) -> None:
        """A killed flow lands here too; the refusal record is already written, so skip it."""
        self.scope.release_slot(flow.metadata.pop("hunt_lease", ""))
        if self.broken or "hunt_tid" not in flow.metadata:
            return
        if flow.metadata.get("hunt_refused"):
            return
        self.transcript.write({
            "id": flow.metadata["hunt_tid"], "ts": S._now(), "identity": "ext",
            "primitive": self.primitive, "tool": self.tool,
            "method": flow.request.method, "url": flow.request.pretty_url,
            "error": str(getattr(flow, "error", "") or "connection error"),
            "scope_digest": self.scope.digest()})

    # ------------------------------------------------------------------------ internals ---
    def _kill(self, flow, tid, method: str, url: str, reason: str, rule: str) -> None:
        """Refuse the request, and record the refusal - a scope denial is itself evidence.

        The tool is told 403 rather than being left to hang, so it reports a clean failure instead
        of a timeout the operator might read as the target being down.
        """
        if tid is not None:
            flow.metadata["hunt_refused"] = True
            self.transcript.write({
                "id": tid, "ts": S._now(), "refused": True, "identity": "ext",
                "primitive": self.primitive, "tool": self.tool, "method": method, "url": url,
                "reason": reason, "rule": rule,
                "scope_digest": self.scope.digest() if self.scope else "none"})
        flow.response = _refusal_response(reason, rule)


def _refusal_response(reason: str, rule: str):
    from mitmproxy import http
    return http.Response.make(
        403, f"hunt scope gate refused this request\nrule: {rule}\nreason: {reason}\n".encode(),
        {"Content-Type": "text/plain", "X-Hunt-Scope": "refused"})


def _text(b) -> str:
    if not b:
        return ""
    return b.decode("utf-8", "replace") if isinstance(b, (bytes, bytearray)) else str(b)


def _workdir(slug: str) -> Path:
    """Where the transcript and the shared limits file live.

    HUNT_WORKDIR wins when set, because the gate MUST write to the same directory as the process
    that launched it. Deriving it from the slug independently would be a second source of truth for
    the one path both sides have to agree on - and a gate writing its refusals into a different
    directory looks, from the report's side, exactly like a gate that is not running.
    """
    explicit = os.environ.get("HUNT_WORKDIR", "")
    if explicit:
        return Path(explicit)
    try:
        import _common as C
        return Path(C.workdir(slug))
    except Exception:            # noqa: BLE001 - the addon must start even if _common moves
        return ROOT / "work" / (slug or "ext")


addons = [ScopeGate()]
