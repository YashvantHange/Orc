#!/usr/bin/env python3
"""
End-to-end: can a tool get a packet past the gate?

This is the test that decides whether the external-tooling design is sound at all. Everything else
in the plan assumes that traffic sent by a binary we do not control - sqlmap, ffuf, nuclei - is
subject to the same scope enforcement as the in-house primitives. That assumption is only true if
the proxy actually refuses, on the wire, a request the scope does not authorize.

So this test does not mock anything: it starts a real mitmdump with the real addon, sends real
requests through it with a plain HTTP client that knows nothing about scope.py, and checks both the
response and the transcript.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import requests

ROOT = Path(__file__).resolve().parent.parent
MITMDUMP = ROOT / ".venv" / "Scripts" / "mitmdump.exe"
if not MITMDUMP.exists():
    MITMDUMP = Path(shutil.which("mitmdump") or "mitmdump")

pytestmark = pytest.mark.skipif(
    not Path(MITMDUMP).exists(),
    reason="mitmdump not installed (python tools/install_tools.py --with-offensive)")


def _free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close()
    return p


class _Echo(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"target-reached")

    def log_message(self, *a):
        return


def _serve(port: int) -> HTTPServer:
    srv = HTTPServer(("127.0.0.1", port), _Echo)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _wait(port: int, timeout: float = 20.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


@pytest.fixture()
def gated(tmp_path):
    """A live target, a live decoy, and a live mitmdump enforcing a scope that allows only one."""
    in_scope_port, out_scope_port, proxy_port = _free_port(), _free_port(), _free_port()
    srv_a, srv_b = _serve(in_scope_port), _serve(out_scope_port)

    workdir = tmp_path / "work" / "t"
    (workdir / "web").mkdir(parents=True)
    scope_file = tmp_path / "scope.yml"
    scope_file.write_text(f"""
schema: 1
program:
  name: gate-test
  authorized_by: self-hosted
in_scope:
  schemes: [http]
  hosts: ["127.0.0.1"]
  ports: [{in_scope_port}]
  allow_private: true
limits:
  rps: 50
  burst: 50
  max_requests: 50
""", encoding="utf-8")

    env = {**os.environ,
           "HUNT_SCOPE_FILE": str(scope_file),
           "HUNT_SLUG": "t",
           "HUNT_EXT_TOOL": "pytest",
           "HUNT_WORKDIR": str(workdir),
           "PYTHONPATH": os.pathsep.join([str(ROOT / "dynamic"), str(ROOT / "static")]),
           "PYTHONUTF8": "1"}
    proc = subprocess.Popen(
        [str(MITMDUMP), "-q", "--listen-host", "127.0.0.1", "-p", str(proxy_port),
         "-s", str(ROOT / "dynamic" / "mitm_gate.py"),
         "--set", f"confdir={tmp_path / 'mitm'}"],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    if not _wait(proxy_port):
        proc.kill()
        pytest.skip(f"mitmdump did not come up: {proc.stdout.read()[:800]!r}")

    proxies = {"http": f"http://127.0.0.1:{proxy_port}"}
    try:
        yield {"proxies": proxies, "in_scope": in_scope_port, "out_scope": out_scope_port,
               "transcript": workdir / "web" / "transcript.jsonl", "proc": proc}
    finally:
        proc.kill()
        srv_a.shutdown(); srv_b.shutdown()


def _records(path: Path) -> list:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return out


def test_in_scope_request_passes_and_is_transcribed(gated):
    r = requests.get(f"http://127.0.0.1:{gated['in_scope']}/api/x",
                     proxies=gated["proxies"], timeout=20)
    assert r.status_code == 200
    assert r.text == "target-reached"

    sent = [x for x in _records(gated["transcript"]) if x.get("status") == 200]
    assert sent, "an allowed request must leave a citable T##### record"
    assert sent[-1]["primitive"] == "ext:pytest"
    assert sent[-1]["id"].startswith("T")


def test_out_of_scope_request_never_reaches_the_target(gated):
    """The one that matters. The client asks for a host the scope does not authorize."""
    r = requests.get(f"http://127.0.0.1:{gated['out_scope']}/api/x",
                     proxies=gated["proxies"], timeout=20)

    assert r.status_code == 403
    assert "target-reached" not in r.text, "the request reached the target despite the scope"
    assert r.headers.get("X-Hunt-Scope") == "refused"

    refused = [x for x in _records(gated["transcript"]) if x.get("refused")]
    assert refused, "a refusal is evidence and must be transcribed"
    assert refused[-1]["rule"], "a refusal must name the rule that produced it"


def test_the_budget_stops_the_tool(gated):
    """max_requests is 50; a tool that keeps going gets cut off rather than being trusted."""
    last = None
    for _ in range(60):
        last = requests.get(f"http://127.0.0.1:{gated['in_scope']}/api/x",
                            proxies=gated["proxies"], timeout=20)
    assert last.status_code == 403
    assert "budget" in last.text.lower()


def test_one_transcript_line_per_id(gated):
    """`hunt evidence --transcript-ids` selects by id, so an id must identify ONE record.

    Two earlier bugs both broke this: reserving an id by writing a placeholder line into the
    transcript, and the gate transcribing a refused flow a second time from the response hook
    (a refusal sets flow.response, which makes mitmproxy fire that hook too).
    """
    requests.get(f"http://127.0.0.1:{gated['in_scope']}/api/x",
                 proxies=gated["proxies"], timeout=20)
    requests.get(f"http://127.0.0.1:{gated['out_scope']}/api/x",
                 proxies=gated["proxies"], timeout=20)

    recs = [r for r in _records(gated["transcript"]) if r.get("id")]
    ids = [r["id"] for r in recs]
    dupes = {i for i in ids if ids.count(i) > 1}
    assert not dupes, f"transcript ids appearing on more than one line: {sorted(dupes)}"
    assert not any(r.get("reserved") for r in recs),         "id reservation must not leave placeholder lines in the transcript"
    assert len(recs) == 2, f"expected exactly one record per request, got {len(recs)}"
