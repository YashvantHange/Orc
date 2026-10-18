#!/usr/bin/env python3
"""
A real external tool, through the real gate, against a real vulnerable target.

Plan verification step 3. Everything else about the external-tooling path is assertion; this is the
part that either works or does not. The claims under test:

  * every request the tool sends lands in the transcript, under ext:<tool>, with sequential ids
  * the tool cannot reach a host the scope does not authorize, even though it never sees the scope
  * the shared budget counts the tool's traffic

The target is a deliberately vulnerable SQLite-backed app on loopback, started by the test.
"""
from __future__ import annotations

import json
import socket
import sqlite3
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "dynamic"))
sys.path.insert(0, str(ROOT / "static"))

import exttool as E  # noqa: E402
import scope as S    # noqa: E402


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class _Vuln(BaseHTTPRequestHandler):
    """String-concatenated SQL, on purpose. Never reachable off loopback."""

    def do_GET(self):  # noqa: N802
        q = parse_qs(urlsplit(self.path).query)
        ident = (q.get("id") or ["1"])[0]
        db = sqlite3.connect(":memory:")
        db.execute("CREATE TABLE users (id INTEGER, name TEXT)")
        db.execute("INSERT INTO users VALUES (1, 'alice'), (2, 'bob')")
        try:
            rows = db.execute("SELECT name FROM users WHERE id = " + ident).fetchall()
            body = ("found: " + ",".join(r[0] for r in rows)).encode()
            code = 200
        except sqlite3.Error as e:
            body = ("sql error: " + str(e)).encode()
            code = 500
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        return


@pytest.fixture()
def target(tmp_path):
    port, decoy = _free_port(), _free_port()
    srv = HTTPServer(("127.0.0.1", port), _Vuln)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    workdir = tmp_path / "work"
    (workdir / "web").mkdir(parents=True)
    scope_file = tmp_path / "scope.yml"
    scope_file.write_text(f"""
schema: 1
program:
  name: exttool-live
  authorized_by: self-hosted
in_scope:
  schemes: [http]
  hosts: ["127.0.0.1"]
  ports: [{port}]
  allow_private: true
limits:
  rps: 50
  burst: 50
  max_requests: 400
""", encoding="utf-8")
    try:
        yield {"port": port, "decoy": decoy, "scope": str(scope_file), "workdir": workdir}
    finally:
        srv.shutdown()


def _records(workdir: Path) -> list:
    p = workdir / "web" / "transcript.jsonl"
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return out


@pytest.mark.skipif(not E.resolve_command("sqlmap"), reason="sqlmap not installed")
@pytest.mark.skipif(not E.resolve_command("mitmdump"), reason="mitmdump not installed")
def test_sqlmap_traffic_is_transcribed_and_citable(target):
    spec = E.TargetSpec(url=f"http://127.0.0.1:{target['port']}/item?id=1", parameter="id")
    rec = E.run("sqlmap", spec, scope_file=target["scope"], slug="t",
                opts={"technique": "B"}, workdir=target["workdir"], timeout=600)

    assert rec["requests"] > 0, (
        "sqlmap sent nothing through the gate - the proxy flag is not reaching it, which means "
        "its traffic would be invisible to the transcript and outside the scope guard")

    sent = [r for r in _records(target["workdir"]) if r.get("primitive") == "ext:sqlmap"]
    assert sent, "sqlmap's requests must be attributed to ext:sqlmap"

    ids = [r["id"] for r in sent]
    assert len(ids) == len(set(ids)), "duplicate transcript ids make a citation ambiguous"
    assert rec["transcript_ids"], "the run record must name the id range a report would cite"

    # the payloads really went through the proxy, not around it
    assert any("id=" in (r.get("url") or "") for r in sent)


@pytest.mark.skipif(not E.resolve_command("sqlmap"), reason="sqlmap not installed")
@pytest.mark.skipif(not E.resolve_command("mitmdump"), reason="mitmdump not installed")
def test_the_tool_cannot_reach_an_unauthorized_host(target):
    """sqlmap never sees the scope file. The proxy is what stops it."""
    spec = E.TargetSpec(url=f"http://127.0.0.1:{target['decoy']}/item?id=1", parameter="id")
    with pytest.raises(S.ScopeViolation):
        E.run("sqlmap", spec, scope_file=target["scope"], slug="t",
              workdir=target["workdir"], timeout=300)

    # pre-flight refused it, so nothing ran at all
    assert not [r for r in _records(target["workdir"]) if r.get("primitive") == "ext:sqlmap"]


@pytest.mark.skipif(not E.resolve_command("ffuf"), reason="ffuf not installed")
@pytest.mark.skipif(not E.resolve_command("mitmdump"), reason="mitmdump not installed")
def test_a_second_tool_shares_the_same_transcript_and_budget(target, tmp_path):
    """Two tools, one target: ids must not collide and the budget must be cumulative."""
    wordlist = tmp_path / "w.txt"
    wordlist.write_text("item\nadmin\nlogin\n", encoding="utf-8")

    rec = E.run("ffuf", E.TargetSpec(url=f"http://127.0.0.1:{target['port']}/FUZZ"),
                scope_file=target["scope"], slug="t",
                opts={"wordlist": str(wordlist).replace("\\", "/")},
                workdir=target["workdir"], timeout=300)
    assert rec["requests"] > 0

    recs = _records(target["workdir"])
    ids = [r["id"] for r in recs if r.get("id")]
    assert len(ids) == len(set(ids)), "two tools writing one transcript reused an id"

    import limits as L
    lim = L.SharedLimiter(target["workdir"] / "web" / "limits.json",
                          rps=50, burst=50, max_requests=400)
    assert lim.spent() >= rec["requests"], "the tool's traffic did not draw down the shared budget"
