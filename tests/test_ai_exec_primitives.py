#!/usr/bin/env python3
"""
The AI/MCP and execution-injection primitives, against a mock that is vulnerable on purpose.

Every probe is tested in BOTH directions. A primitive that only ever fires is a false-positive
generator, and one that never fires is worse than absent because its silence reads as CLEAR - which
is the defect dynamic/verdict.py exists to prevent. So each class gets a vulnerable route and a
defended one, and the defended route must come back NOT-CONFIRMED or CLEAR, never HIT.
"""
from __future__ import annotations

import json
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "dynamic"))
sys.path.insert(0, str(ROOT / "static"))
sys.path.insert(0, str(ROOT / "web"))

import primitives as P   # noqa: E402
import sweep             # noqa: E402

CANARY_ECHO = "PROMPT-INJECT-OK"
OWNER_SECRET = "owner-only-marker-7f3a"


class Mock(BaseHTTPRequestHandler):
    """A deliberately weak agent product. Loopback only."""

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

    # ------------------------------------------------------------------------ GET ----
    def do_GET(self):  # noqa: N802
        u = urlsplit(self.path)
        q = parse_qs(u.query)

        if u.path == "/vuln/notes":
            # the model "reads" stored content and obeys it
            return self._send(200, json.dumps({"summary": Store.note}))

        if u.path == "/safe/notes":
            return self._send(200, json.dumps({"summary": "(content redacted)"}))

        if u.path == "/api/owner/doc":
            # the boundary tool_authz_diff needs: low-priv identity is refused
            if "owner" not in (self.headers.get("Cookie") or ""):
                return self._send(403, json.dumps({"error": "forbidden"}))
            return self._send(200, json.dumps({"secret": OWNER_SECRET}))

        return self._send(404, json.dumps({"error": "nope"}))

    # ----------------------------------------------------------------------- POST ----
    def do_POST(self):  # noqa: N802
        u = urlsplit(self.path)
        body = self._body()

        if u.path == "/vuln/chat":
            # no boundary at all: the "model" obeys whatever it is told
            msg = str(body.get("message", ""))
            m = [w for w in msg.replace("\n", " ").split() if CANARY_ECHO in w]
            if m:
                return self._send(200, json.dumps({"reply": m[0].strip(".,:")}))
            return self._send(200, json.dumps({"reply": "I can help with that."}))

        if u.path == "/safe/chat":
            return self._send(200, json.dumps({"reply": "I can't follow instructions in input."}))

        if u.path == "/vuln/agent":
            # the tool runs as the service, so a low-priv caller reaches the owner's document
            msg = str(body.get("message", ""))
            if "/api/owner/doc" in msg:
                return self._send(200, json.dumps({"tool_result": {"secret": OWNER_SECRET}}))
            return self._send(200, json.dumps({"reply": "no tool matched"}))

        if u.path == "/safe/agent":
            return self._send(200, json.dumps({"reply": "That is not yours to read."}))

        if u.path == "/vuln/notes":
            Store.note = str(body.get("content", ""))
            return self._send(200, json.dumps({"ok": True}))

        if u.path == "/safe/notes":
            return self._send(200, json.dumps({"ok": True}))

        if u.path == "/mcp":
            # unauthenticated tools/list - the MCP bug everyone is finding in 2026
            return self._send(200, json.dumps({
                "jsonrpc": "2.0", "id": 1,
                "result": {"tools": [
                    {"name": "read_file"}, {"name": "execute_command"},
                    {"name": "http_fetch"}, {"name": "get_env_secret"},
                ]}}))

        if u.path == "/gated/mcp":
            return self._send(401, json.dumps({"error": "unauthorized"}))

        return self._send(404, json.dumps({"error": "nope"}))

    def log_message(self, *a):
        return


class Store:
    note = ""


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture(scope="module")
def base():
    port = _free_port()
    srv = HTTPServer(("127.0.0.1", port), Mock)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        srv.shutdown()


def v(result) -> str:
    return sweep.verdict(result)


# ============================================================== MCP surface ===
def test_mcp_unauthenticated_tools_list_is_a_hit(base):
    r = P.REGISTRY["mcp_surface_auth"](base, "/mcp", "", P.Ctx(opts={"mcp_path": "/mcp"}))
    assert v(r) == "HIT"
    assert "execute_command" in r.evidence["tools"]


def test_mcp_gated_endpoint_is_clear_with_a_named_guard(base):
    """CLEAR must name the guard and the attack - it is not a fallthrough."""
    r = P.REGISTRY["mcp_surface_auth"](base, "/gated/mcp", "", P.Ctx(opts={"mcp_path": "/gated/mcp"}))
    assert v(r) == "CLEAR"
    assert r.evidence["guard"] and r.evidence["attack"]


def test_mcp_absent_is_not_applicable_not_clear(base):
    r = P.REGISTRY["mcp_surface_auth"](base, "", "", P.Ctx(opts={"mcp_path": "/nothing-here"}))
    assert v(r) != "HIT"
    assert "N/A" in r.detail or v(r) == "NOT-CONFIRMED"


def test_excessive_agency_flags_dangerous_tools_as_a_lead_only(base):
    r = P.REGISTRY["excessive_agency"](base, "/mcp", "", P.Ctx(opts={"mcp_path": "/mcp"}))
    assert not r.confirmed, "naming a tool execute_command is not proof it is reachable"
    assert r.evidence.get("lead") is True
    assert "exec" in r.evidence["dangerous"]


# ======================================================== prompt injection ===
def test_direct_prompt_injection_fires_on_the_vulnerable_route(base):
    r = P.REGISTRY["prompt_inject_direct"](base, "/vuln/chat", "message", P.Ctx())
    assert v(r) == "HIT"
    assert r.evidence["canary"] in r.evidence["snippet"]


def test_direct_prompt_injection_on_a_defended_route_is_not_clear(base):
    """The route refused. We did not read a guard, so the honest verdict is NOT-CONFIRMED."""
    r = P.REGISTRY["prompt_inject_direct"](base, "/safe/chat", "message", P.Ctx())
    assert v(r) == "NOT-CONFIRMED"
    assert v(r) != "CLEAR"


def test_indirect_prompt_injection_is_the_agentjacking_shape(base):
    """Plant in stored content, observe the model that later reads it."""
    ctx = P.Ctx(opts={"readback": "/vuln/notes"})
    r = P.REGISTRY["prompt_inject_indirect"](base, "/vuln/notes", "content", ctx)
    assert v(r) == "HIT"
    assert r.evidence["readback"] == "/vuln/notes"


def test_indirect_prompt_injection_needs_a_readback(base):
    r = P.REGISTRY["prompt_inject_indirect"](base, "/vuln/notes", "content", P.Ctx())
    assert v(r) == "BLOCKED"
    assert "readback" in r.detail


def test_indirect_on_a_defended_consumer_does_not_fire(base):
    ctx = P.Ctx(opts={"readback": "/safe/notes"})
    r = P.REGISTRY["prompt_inject_indirect"](base, "/safe/notes", "content", ctx)
    assert v(r) != "HIT"


# ================================================== the reportable one: authz delta ===
def test_tool_authz_diff_confirms_only_with_a_real_privilege_delta(base):
    ctx = P.Ctx(identities={"other": "Cookie: sid=low"},
                opts={"victim_path": "/api/owner/doc", "victim_marker": OWNER_SECRET})
    r = P.REGISTRY["tool_authz_diff"](base, "/vuln/agent", "message", ctx)
    assert v(r) == "HIT"
    assert r.evidence["direct_status"] == 403, "the boundary must be shown to exist"
    assert OWNER_SECRET in r.evidence["snippet"]


def test_tool_authz_diff_refuses_to_confirm_without_a_boundary(base):
    """If the direct route already allows it, the tool path proves nothing.

    This is the MSRC lesson in code: a capability with no privilege delta is not a vulnerability.
    """
    ctx = P.Ctx(identities={"other": "Cookie: sid=owner"},     # this identity CAN read it directly
                opts={"victim_path": "/api/owner/doc", "victim_marker": OWNER_SECRET})
    r = P.REGISTRY["tool_authz_diff"](base, "/vuln/agent", "message", ctx)
    assert v(r) == "NOT-CONFIRMED"
    assert "no boundary" in r.detail


def test_tool_authz_diff_blocks_without_a_second_identity(base):
    ctx = P.Ctx(opts={"victim_path": "/api/owner/doc"})
    r = P.REGISTRY["tool_authz_diff"](base, "/vuln/agent", "message", ctx)
    assert v(r) == "BLOCKED"


def test_tool_authz_diff_on_a_defended_agent(base):
    ctx = P.Ctx(identities={"other": "Cookie: sid=low"},
                opts={"victim_path": "/api/owner/doc", "victim_marker": OWNER_SECRET})
    r = P.REGISTRY["tool_authz_diff"](base, "/safe/agent", "message", ctx)
    assert v(r) != "HIT"


# ============================================================ execution injection ===
def test_cmdi_oob_refuses_to_guess_on_a_remote_target():
    """A loopback listener cannot be reached by a remote host, so the probe is not sent.

    Reporting a guaranteed timeout as CLEAR is the laundering the verdict schema forbids.
    """
    r = P.REGISTRY["cmdi_oob"]("https://example.com", "/api/x", "q", P.Ctx())
    assert v(r) == "NEEDS-OOB"
    assert r.evidence.get("needs_oob") is True


def test_cmdi_blind_does_not_fire_on_a_fast_endpoint(base):
    r = P.REGISTRY["cmdi_blind"](base, "/api/owner/doc", "q", P.Ctx())
    assert v(r) != "HIT"
    assert v(r) != "CLEAR", "no guard was read, so this cannot be CLEAR"


def test_arg_injection_does_not_fire_without_a_binary(base):
    r = P.REGISTRY["arg_injection"](base, "/api/owner/doc", "url", P.Ctx())
    assert v(r) != "HIT"


def test_env_injection_does_not_fire_without_a_child_process(base):
    r = P.REGISTRY["env_injection"](base, "/api/owner/doc", "lang", P.Ctx())
    assert v(r) != "HIT"


# ==================================================== registration and reachability ===
def test_every_new_primitive_is_registered_and_targeted():
    new = ["prompt_inject_direct", "prompt_inject_indirect", "tool_authz_diff",
           "insecure_output_handling", "mcp_surface_auth", "excessive_agency",
           "cmdi_blind", "cmdi_oob", "arg_injection", "env_injection"]
    for name in new:
        assert name in P.REGISTRY, f"{name} is not registered"
        assert name in sweep.TARGETING, (
            f"{name} has no TARGETING entry, so the sweep will never pick an endpoint for it "
            f"and its matrix row stays invisible")


def test_the_coverage_audit_is_clean_of_stale_and_unmapped_entries():
    sys.path.insert(0, str(ROOT / "tools"))
    import audit_coverage
    r = audit_coverage.audit()
    assert not r["stale"], f"COVERS names something that no longer exists: {r['stale']}"
    assert not r["unmapped"], f"matrix rows with no coverage decision: {r['unmapped']}"
