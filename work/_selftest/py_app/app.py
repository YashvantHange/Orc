#!/usr/bin/env python3
"""
py_app - a deliberately vulnerable Python fixture for the local-target dynamic pipeline.

**DO NOT FIX THE BUGS IN THIS FILE.** They are seeded on purpose. `dynamic/probe.py`'s
`selftest_plan` and `dynamic/authz_diff.py`'s `SELFTEST_CONFIG` are written against these exact
routes, and `tests/test_orchestration.py` asserts this directory exists.

It is the counterpart of `../src_app` (read, never run) and `../web_app` (a Flask app driven through
the live-website sweep). This one is the fixture the four dynamic entrypoints name in their own
usage lines:

    python dynamic/probe.py      --launch work/_selftest/py_app --selftest
    python dynamic/authz_diff.py --launch work/_selftest/py_app --selftest
    python dynamic/fuzz.py       --launch work/_selftest/py_app --endpoint /calc --param expr
    python dynamic/run_target.py work/_selftest/py_app --seconds 120

STDLIB ONLY, on purpose. `dynamic/instrument.py` boots a python target in a fresh `.dynvenv` and
only pip-installs when a `requirements.txt` is present. A fixture that needed Flask would therefore
need a network install before the self-test could run at all - so this one needs nothing but the
interpreter, including for its HS256 tokens. `../web_app` imports Flask because it is launched by
hand from the repo venv, never through `instrument.py`.

Binds 127.0.0.1 only, on $PORT. Identities: alice/pw-alice, bob/pw-bob, viewer/pw-viewer.
`/safe/*` routes are the negative controls: correctly defended, same shape. A run that reports one
of them is producing false positives, which is the whole reason they are here.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

HERE = Path(__file__).resolve().parent
PORT = int(os.environ.get("PORT", "8011"))

# ---- seed: authn-hardcoded-secret -----------------------------------------------------------
# The signing key is a constant in the source, so anyone who can read the source can mint a token
# for any subject. `dynamic/probe.py`'s jwt_forgery primitive is handed this exact string by
# selftest_plan and confirms by seeing its forged `sub` echoed back.
JWT_SECRET = "hardcoded-self-test-secret-do-not-use"

USERS = {"alice": "pw-alice", "bob": "pw-bob", "viewer": "pw-viewer"}

# The marker has to really be in the owner's record: the authorization differential confirms an
# IDOR by seeing the OWNER's marker come back in some OTHER identity's response.
ITEMS = {
    "1": {"id": 1, "owner": "alice", "note": "alice-private-note"},
    "2": {"id": 2, "owner": "bob", "note": "bob-private-note"},
}


# ------------------------------------------------------------------------------ JWT (manual) ---
def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwt_encode(payload: dict) -> str:
    head = _b64u(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    body = _b64u(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(JWT_SECRET.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{_b64u(sig)}"


def jwt_decode(token: str) -> dict | None:
    """Verify HS256 against JWT_SECRET. `alg: none` is rejected - the seed is the key, not the alg.

    The signature IS checked, so the forgery that lands is the one that uses the leaked constant
    above. A probe run that reports the `alg_none` variant against this fixture is wrong.
    """
    try:
        head, body, sig = token.split(".")
        alg = json.loads(_b64u_dec(head)).get("alg", "")
        if alg != "HS256":
            return None
        want = hmac.new(JWT_SECRET.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(_b64u(want), sig):
            return None
        return json.loads(_b64u_dec(body))
    except (ValueError, KeyError, json.JSONDecodeError):
        return None


class Handler(BaseHTTPRequestHandler):
    server_version = "py_app-fixture"

    # ------------------------------------------------------------------------- plumbing ---
    def log_message(self, *a):          # keep the fixture quiet in server.log
        return

    def _send(self, code: int, body: str, ctype: str = "application/json",
              headers: dict | None = None) -> None:
        raw = body.encode("utf-8", "replace")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def _json(self, code: int, obj) -> None:
        self._send(code, json.dumps(obj))

    def _identity(self) -> str | None:
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        claims = jwt_decode(auth[7:])
        return claims.get("sub") if claims else None

    # ------------------------------------------------------------------------- dispatch ---
    def do_POST(self):                                              # noqa: N802
        path = urlsplit(self.path).path
        if path == "/login":
            try:
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}")
            except (ValueError, json.JSONDecodeError):
                return self._json(400, {"error": "bad json"})
            user, pw = body.get("user", ""), body.get("password", "")
            if USERS.get(user) == pw:
                return self._json(200, {"token": jwt_encode({"sub": user})})
            return self._json(401, {"error": "bad credentials"})
        return self._json(404, {"error": "no such route"})

    def do_GET(self):                                               # noqa: N802
        u = urlsplit(self.path)
        path, q = u.path, parse_qs(u.query)
        one = lambda k, d="": (q.get(k) or [d])[0]                  # noqa: E731

        # ---- seed: cors-reflected-origin-with-credentials ---------------------------------
        # Reflects whatever Origin arrives AND allows credentials, so any site can read the
        # authenticated response. The pair is the bug; either alone is not.
        if path == "/":
            origin = self.headers.get("Origin", "")
            hdrs = {"Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Credentials": "true"} if origin else {}
            return self._send(200, json.dumps({"app": "py_app", "ok": True}), headers=hdrs)

        # ---- seed: missing-auth-admin-endpoint ---------------------------------------------
        # An administrative route with no authentication check at all.
        if path == "/admin/secret":
            return self._json(200, {"api_key": "AKIA-FIXTURE-0000-NOT-REAL",
                                    "admin": True, "note": "no authentication required"})

        if path == "/me":
            who = self._identity()
            if not who:
                return self._json(401, {"error": "no valid token"})
            return self._json(200, {"sub": who, "authenticated": True})

        # ---- seed: idor-missing-ownership-check --------------------------------------------
        # The item id is trusted straight from the path. Ownership is recorded on the record and
        # never compared against the caller, so every identity - including anonymous - reads
        # every item.
        if path.startswith("/items/"):
            item = ITEMS.get(path[len("/items/"):])
            if not item:
                return self._json(404, {"error": "no such item"})
            return self._json(200, item)

        # ---- negative control: same shape, ownership enforced ------------------------------
        if path.startswith("/safe/items/"):
            who = self._identity()
            item = ITEMS.get(path[len("/safe/items/"):])
            if not item:
                return self._json(404, {"error": "no such item"})
            if item["owner"] != who:
                return self._json(403, {"error": "not your item"})
            return self._json(200, item)

        # ---- seed: path-traversal + error-disclosure ---------------------------------------
        # The parameter is joined onto a base directory with no containment check, so `../` walks
        # out of it. The except clause then returns the raw exception, which is a second, separate
        # seed: `dynamic/probe.py`'s error_disclosure primitive aims at this same route.
        if path == "/read":
            rel = one("path", "README.md")
            try:
                return self._send(200, (HERE / rel).read_text(encoding="utf-8", errors="replace"),
                                  "text/plain")
            except OSError as e:
                return self._send(500, json.dumps({
                    "error": str(e),
                    "traceback": f'  File "{__file__}", line ?, in do_GET\n'
                                 f"    (HERE / rel).read_text(...)\n{type(e).__name__}: {e}",
                }))

        # ---- negative control: resolved-path containment ------------------------------------
        if path == "/safe/read":
            rel = one("path", "README.md")
            try:
                target = (HERE / rel).resolve()
                target.relative_to(HERE)                        # raises if it escaped
                return self._send(200, target.read_text(encoding="utf-8", errors="replace"),
                                  "text/plain")
            except (OSError, ValueError):
                return self._json(400, {"error": "bad path"})    # no internals in the response

        # ---- seed: reflected-xss ------------------------------------------------------------
        # Interpolated into an HTML response with no escaping. The content type matters: the
        # primitive only confirms when the reflection lands in a document a browser parses.
        if path == "/greet":
            name = one("name", "world")
            return self._send(200, f"<html><body><h1>hello {name}</h1></body></html>",
                              "text/html; charset=utf-8")

        # ---- negative control: escaped on output -------------------------------------------
        if path == "/safe/greet":
            name = html.escape(one("name", "world"))
            return self._send(200, f"<html><body><h1>hello {name}</h1></body></html>",
                              "text/html; charset=utf-8")

        # ---- seed: expression-injection -----------------------------------------------------
        # eval() on a request parameter. 7*7 -> 49 is the benign marker the primitive uses; the
        # same sink takes __import__, which is why this is code execution and not a calculator.
        if path == "/calc":
            expr = one("expr", "1+1")
            try:
                return self._json(200, {"expr": expr, "result": eval(expr)})  # noqa: S307
            except Exception as e:                                            # noqa: BLE001
                return self._json(400, {"expr": expr, "error": type(e).__name__})

        # ---- negative control: parsed, not evaluated ----------------------------------------
        if path == "/safe/calc":
            import ast
            expr = one("expr", "1+1")
            try:
                return self._json(200, {"expr": expr, "result": ast.literal_eval(expr)})
            except (ValueError, SyntaxError, TypeError):
                return self._json(400, {"expr": expr, "error": "not a literal"})

        return self._json(404, {"error": "no such route"})


def main() -> int:
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"py_app fixture listening on http://127.0.0.1:{PORT}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
