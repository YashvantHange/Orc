#!/usr/bin/env python3
"""
sweep.py — run every applicable primitive against a live target and report per-class verdicts.

This is the completeness enforcement. Coverage is not "I ran some probes"; it is a verdict for every
row of the matrix in `vuln-playbooks`, each one HIT / CLEAR / N/A / BLOCKED with a reason. A class
nobody could test comes back BLOCKED — never CLEAR — and the classes that only a browser or a human
can settle are listed explicitly as NEEDS-BROWSER / MANUAL with the recipe to use.

  python web/sweep.py https://app.example.com --scope scope.yml --all

The primitives are accelerators. Every row the runner cannot close names the `web-playbooks` section
whose curl you can type yourself, so a missing primitive is never an excuse for an unswept class.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for sub in ("dynamic", "static", "web"):
    sys.path.insert(0, str(ROOT / sub))

import scope as S            # noqa: E402
import _common as C          # noqa: E402
import probe                 # noqa: E402
import primitives as P       # noqa: E402

# Which endpoints a primitive wants. `param_hints` picks the parameter to attack; `path_hints`
# narrows the endpoint list. Empty means "the site root / any endpoint".
TARGETING = {
    "sqli_error":       {"param_hints": ["q", "search", "query", "id", "name", "filter", "sort"]},
    "sqli_boolean":     {"param_hints": ["q", "search", "query", "id", "name", "filter"]},
    "sqli_time":        {"param_hints": ["q", "search", "query", "id"]},
    "nosqli":           {"param_hints": ["user", "username", "email", "id", "filter"]},
    "ssti":             {"param_hints": ["tpl", "template", "preview", "name", "q", "message"]},
    "lfi_rfi":          {"param_hints": ["file", "path", "page", "include", "template", "doc"]},
    "open_redirect":    {"param_hints": ["next", "url", "redirect", "return", "returnUrl",
                                         "continue", "dest", "target", "r", "u"]},
    "second_order":     {"param_hints": ["value", "name", "display_name", "comment", "bio"]},
    "xxe":              {"path_hints": ["import", "xml", "upload", "parse", "soap", "feed"]},
    "proto_pollution_server": {"path_hints": ["settings", "config", "preferences", "profile",
                                              "merge", "update"]},
    "deserial_cookie":  {},
    "idor_enum":        {"templated": True},
    "bfla_matrix":      {"path_hints": ["admin", "users", "internal", "manage", "settings",
                                        "billing", "export"]},
    "mass_assignment":  {"path_hints": ["profile", "user", "account", "me", "settings"]},
    "method_override":  {"templated": True},
    "rate_limit":       {"path_hints": ["login", "signin", "auth", "token", "otp", "verify"]},
    "csrf":             {"path_hints": ["profile", "settings", "account", "update", "email"]},
    "clickjacking_header": {"path_hints": ["account", "settings", "delete", "profile", "billing",
                                           "authorize", "transfer"]},
    "cors_variants":    {"path_hints": ["api", "me", "user", "account"]},
    "host_header":      {},
    "cache_deception":  {"path_hints": ["account", "profile", "me", "dashboard", "settings"]},
    "cache_poison":     {},
    "smuggling_detect": {},
    "upload_bypass":    {"path_hints": ["upload", "file", "attachment", "avatar", "import", "media"]},
    "signed_url_abuse": {"path_hints": ["presign", "sign", "upload-url", "uploads"]},
    "graphql_introspection": {"fixed": "/graphql"},
    "graphql_batching":      {"fixed": "/graphql"},
    "graphql_field_authz":   {"fixed": "/graphql"},
    "ws_auth":          {"fixed": "/ws"},
    "session_fixation": {"fixed": "/api/login"},
    "pwreset_token":    {"path_hints": ["reset", "forgot", "recover"]},
    "oauth_redirect":   {"path_hints": ["authorize", "oauth", "connect"]},
    "jwt_alg_confusion": {"path_hints": ["me", "profile", "user", "token"]},
    "jwt_kid":          {"path_hints": ["me", "profile", "user", "token"]},
    "jwt_jku":          {"path_hints": ["me", "profile", "user", "token"]},
    "subdomain_takeover": {"fixed": "/"},
    "missing_auth":     {"path_hints": ["admin", "internal", "config", "debug", "secret", "key"]},
    "path_traversal":   {"param_hints": ["path", "file", "name", "doc", "download"]},
    "ssrf":             {"param_hints": ["url", "uri", "src", "target", "webhook", "callback",
                                         "image", "fetch", "link"]},
    "xss":              {"param_hints": ["q", "name", "search", "message", "comment", "title"]},
    "expr_injection":   {"param_hints": ["expr", "calc", "formula", "eval"]},
    "error_disclosure": {"param_hints": ["path", "id", "file"]},
    "jwt_forgery":      {"path_hints": ["me", "profile", "user"]},
}

# Matrix rows no primitive settles, even with a browser. Listed so the coverage report can never be
# silently short: each names where the human-runnable recipe lives.
MANUAL_ROWS = {
    "CSTI": ("D", "web-playbooks § CSTI", "NEEDS-BROWSER"),
    "SPA route-guard bypass": ("D", "web-recon § 3 (bundle role checks)", "MANUAL"),
    "Client-side traversal / DOM redirect": ("D", "web-playbooks § Client-side traversal",
                                             "NEEDS-BROWSER"),
    "Business logic & workflow abuse": ("A", "web-playbooks § Business logic", "MANUAL"),
    "SAML": ("A", "web-playbooks § SAML", "MANUAL"),
    "OAuth/OIDC full chain": ("A", "web-playbooks § OAuth & OIDC", "MANUAL"),
    "MFA bypass": ("A", "web-playbooks § Password reset & MFA", "MANUAL"),
    "Race conditions (multi-user)": ("A", "dynamic-hunt §1b (TOCTOU recipe)", "MANUAL"),
    "Prompt injection -> insecure output": ("G", "vuln-playbooks § AI/LLM-native", "MANUAL"),
    "Prompt-to-tool privilege escalation": ("G", "vuln-playbooks § Prompt-to-tool", "MANUAL"),
}

GROUP_NAMES = {"A": "Access control & identity", "B": "Injection & execution",
               "C": "Untrusted fetch & files", "D": "Client-side", "E": "API & protocol",
               "F": "Infrastructure & config", "G": "AI / LLM-native"}


def load_endpoints(workdir: Path) -> list:
    f = workdir / "web" / "endpoints.json"
    if not f.exists():
        return []
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []


# Conventional paths per class, tried when recon's inventory has no strong candidate. A crawl only
# sees what the UI links to; the handlers that never got a button are exactly the under-tested ones.
FALLBACK_PATHS = {
    "sqli_error": ["/search", "/api/search", "/api/items", "/api/users"],
    "sqli_boolean": ["/search", "/api/search", "/api/items", "/api/users"],
    "sqli_time": ["/search", "/api/search"],
    "nosqli": ["/api/find", "/api/search", "/api/users", "/api/login"],
    "ssti": ["/preview", "/api/preview", "/render", "/api/render", "/search"],
    "lfi_rfi": ["/download", "/api/download", "/api/files", "/render"],
    "open_redirect": ["/go", "/redirect", "/api/redirect", "/login", "/logout"],
    "xxe": ["/api/import", "/api/upload", "/import", "/soap", "/api/xml"],
    "proto_pollution_server": ["/api/settings", "/api/config", "/api/preferences", "/api/profile"],
    "second_order": ["/api/profile", "/api/settings"],
    "mass_assignment": ["/api/profile", "/api/me", "/api/account", "/api/users"],
    "upload_bypass": ["/api/upload", "/upload", "/api/files"],
    "signed_url_abuse": ["/api/uploads/presign", "/api/presign", "/api/upload-url"],
    "rate_limit": ["/api/login", "/login", "/api/auth/login"],
    "session_fixation": ["/api/login", "/login"],
    "pwreset_token": ["/api/password/reset", "/api/password/forgot", "/forgot-password"],
    "oauth_redirect": ["/oauth/authorize", "/authorize", "/oauth2/authorize"],
    "host_header": ["/api/password/reset", "/", "/login"],
    "csrf": ["/api/profile", "/api/settings", "/api/account"],
    "clickjacking_header": ["/account", "/settings", "/settings/delete-account", "/profile"],
    "cache_deception": ["/account", "/api/me", "/profile", "/dashboard"],
    "bfla_matrix": ["/api/admin/users", "/api/admin", "/api/users", "/api/internal/audit-log"],
    "method_override": ["/api/items/{id}", "/api/profile"],
    "missing_auth": ["/api/admin/users", "/api/internal/audit-log", "/actuator/env", "/api/config"],
    "path_traversal": ["/download", "/api/files", "/render"],
    "ssrf": ["/api/fetch", "/proxy", "/api/proxy", "/api/webhook", "/preview"],
    "xss": ["/search", "/preview", "/greet"],
    "expr_injection": ["/calc", "/api/calc", "/eval"],
    "error_disclosure": ["/search", "/api/items"],
    "ws_auth": ["/ws", "/socket.io/", "/api/stream", "/events"],
    "deserial_cookie": ["/api/me", "/"],
    "graphql_field_authz": ["/graphql", "/api/graphql"],
}


def pick_targets(name: str, endpoints: list, limit: int = 6) -> list:
    """Endpoints worth pointing this primitive at, strongest evidence first.

    Ranking matters more than breadth: a parameter whose NAME matches the class (`?next=` for open
    redirect) is a far better guess than the first endpoint that happens to have any parameter, and
    picking wrong is how a real bug gets recorded as `clear`.
    """
    t = TARGETING.get(name, {})
    if t.get("fixed"):
        paths = [t["fixed"]] + [p for p in FALLBACK_PATHS.get(name, []) if p != t["fixed"]]
        return [(p, "") for p in paths[:limit]]

    scored: list = []            # (rank, path, param) — lower rank is tried first

    if t.get("templated"):
        for e in endpoints:
            if "{id}" in e.get("path", ""):
                # a real object route beats /api/safe/* twins, which exist to be defended
                scored.append((0 if "/safe/" not in e["path"] else 5, e["path"], ""))
    ph = [h.lower() for h in t.get("param_hints", [])]
    if ph:
        for e in endpoints:
            # GraphQL multiplexes everything behind one path, so its argument names would otherwise
            # win every param match and pull generic primitives onto /graphql. It has its own.
            if "graphql" in e.get("path", "").lower():
                continue
            for p in e.get("params", []):
                nm = (p.get("name") or "").lower()
                if nm in ph:
                    # earlier in the hint list = more characteristic of this class
                    scored.append((1 + ph.index(nm) * 0.01, e["path"], p["name"]))
    hints = [h.lower() for h in t.get("path_hints", [])]
    if hints:
        for e in endpoints:
            low = e.get("path", "").lower()
            for i, h in enumerate(hints):
                if h in low:
                    scored.append((2 + i * 0.01 + (3 if "/safe/" in low else 0), e["path"], ""))
                    break
    # discovered-but-unparameterized endpoints, tried with the class's canonical parameter name
    if ph:
        for e in endpoints:
            if e.get("method") == "GET" and not e.get("params"):
                scored.append((4, e["path"], ph[0]))
    # conventional paths, whether or not recon found them
    for i, p in enumerate(FALLBACK_PATHS.get(name, [])):
        scored.append((3 + i * 0.01, p, ph[0] if ph else ""))

    scored.sort(key=lambda s: s[0])
    seen, out = set(), []
    for _rank, path, param in scored:
        key = (path, param)
        if key not in seen:
            seen.add(key)
            out.append(key)
    return out[:limit] or [("/", "")]


def run_browser(base: str, workdir: Path, ctx: P.Ctx, scope, slug: str) -> list:
    """The six checks that need a real browser. Returns NEEDS-BROWSER results when one is absent —
    a class you could not execute is never a CLEAR."""
    try:
        import browser as B
    except ImportError as e:
        return [P.ProbeResult(n, False, "", detail=f"NEEDS-BROWSER: {e}",
                              evidence={"needs_browser": True}) for n in
                ("dom_xss", "clickjacking", "postmessage_origin", "proto_pollution_client",
                 "cookie_flags_effective", "csp_effective")]
    eps = load_endpoints(workdir)

    def rank(path: str) -> int:
        """Real pages before soft-404 shells.

        On a target that answers 200 + HTML for unknown paths, every /api/* route looks like an HTML
        page. Taking the first N by discovery order then fills the candidate list with shells and
        never reaches the pages that actually carry a DOM sink.
        """
        if path.endswith(".html"):
            return 0                                   # standalone assets: dom.html, pm.html
        if path.startswith("/api/") or path.startswith("/graphql"):
            return 3                                   # almost certainly the shell, not a page
        if path == "/":
            return 1
        return 2                                       # real app routes

    html = [e["path"] for e in eps
            if e.get("content_type", "").startswith("text/html") and "{id}" not in e["path"]]
    html += [e["path"] for e in eps if e["path"].endswith(".html") and e["path"] not in html]
    dom = sorted(dict.fromkeys(html), key=lambda p: (rank(p), p))[:10] or ["/"]
    sensitive = next((e["path"] for e in eps
                      if any(h in e["path"].lower()
                             for h in ("account", "settings", "delete", "profile", "billing"))), "/")
    cookie = ctx.identities.get("owner", "")
    return B.run_all(scope, slug, base, dom_candidates=dom, sensitive_path=sensitive, cookie=cookie)


def run(base: str, workdir: Path, ctx: P.Ctx, only: list | None = None,
        skip_slow: bool = False) -> dict:
    endpoints = load_endpoints(workdir)
    names = only or sorted(probe.PRIMITIVES)
    results, by_group = [], {}

    for name in names:
        meta = probe.PRIMITIVE_META.get(name, {})
        group = meta.get("group") or "?"
        if skip_slow and name in ("sqli_time", "smuggling_detect", "rate_limit"):
            results.append(P.blocked(name, "", "skipped by --fast (timing/volume probe)"))
            by_group.setdefault(group, []).append(results[-1])
            continue
        best = None
        for endpoint, param in pick_targets(name, endpoints):
            try:
                r = probe.run_primitive(base, name, endpoint, param=param or None, ctx=ctx)
            except S.ScopeViolation as v:
                r = P.blocked(name, endpoint, f"scope refused this request: {v.reason}")
            except Exception as e:                     # noqa: BLE001 - one bad probe can't end a sweep
                r = P.ProbeResult(name, False, endpoint, detail=f"error: {type(e).__name__}: {e}")
            if r.confirmed:
                best = r
                break
            # a BLOCKED result outranks a plain miss — it means "not tested", not "defended"
            if best is None or (r.evidence.get("blocked") and not best.evidence.get("blocked")):
                best = r
        if best is not None:
            results.append(best)
            by_group.setdefault(group, []).append(best)
    return {"results": results, "by_group": by_group, "endpoints": len(endpoints)}


def verdict(r) -> str:
    if r.confirmed:
        return "HIT"
    if r.evidence.get("blocked"):
        return "BLOCKED"
    if r.evidence.get("needs_browser"):
        return "NEEDS-BROWSER"
    return "CLEAR"


def report(base: str, out: dict, ctx: P.Ctx, workdir: Path) -> int:
    results = out["results"]
    hits = [r for r in results if verdict(r) == "HIT"]
    blocked_ = [r for r in results if verdict(r) == "BLOCKED"]
    nobrowser = [r for r in results if verdict(r) == "NEEDS-BROWSER"]
    clear = [r for r in results if verdict(r) == "CLEAR"]

    print(f"\ncoverage sweep — {base}   ({out['endpoints']} endpoints known)")
    if not ctx.has_baselines():
        print("  ! NO BASELINES LOADED. Run `hunt web recon` first — on a target that soft-404s,")
        print("    every result below is untrustworthy and must be treated as unverified.")

    for g in sorted(out["by_group"]):
        print(f"\n  {g}. {GROUP_NAMES.get(g, g)}")
        for r in sorted(out["by_group"][g], key=lambda x: (not x.confirmed, x.name)):
            v = verdict(r)
            mark = {"HIT": "HIT          ", "BLOCKED": "BLOCKED      ",
                    "NEEDS-BROWSER": "NEEDS-BROWSER", "CLEAR": "clear        "}[v]
            meta = probe.PRIMITIVE_META.get(r.name, {})
            extra = " [detection-only]" if meta.get("detection_only") else ""
            print(f"    [{mark}] {r.name:24} {r.endpoint[:28]:28} {r.detail[:78]}{extra}")

    print("\n  Rows no primitive can settle — these are NOT clear, they are unswept until a human")
    print("  or a browser closes them:")
    for row, (g, where, kind) in sorted(MANUAL_ROWS.items(), key=lambda kv: kv[1][0]):
        print(f"    [{kind:13}] {g}  {row:38} -> {where}")

    print(f"\n  {len(hits)} HIT · {len(blocked_)} BLOCKED · {len(nobrowser)} NEEDS-BROWSER · "
          f"{len(clear)} clear · {len(MANUAL_ROWS)} manual rows outstanding")
    if nobrowser:
        print("  Install the browser to close those rows:")
        print("    .venv/Scripts/python.exe -m pip install playwright && "
              ".venv/Scripts/python.exe -m playwright install chromium")
    if blocked_:
        print("\n  BLOCKED means NOT TESTED. Each needs what it asks for before any verdict is real:")
        for r in blocked_[:12]:
            print(f"    - {r.name}: {r.detail.replace('BLOCKED: ', '')}")
    print("\n  Every `clear` above still needs its enumeration tuple AND the defense you observed")
    print("  before it can be written down as CLEAR (vuln-playbooks § Depth-qualify every verdict).")
    print("  `hunt web coverage <target>` derives the tuple from the transcript.")

    d = workdir / "web"
    d.mkdir(parents=True, exist_ok=True)
    payload = {
        "base": base, "ran_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "endpoints_known": out["endpoints"], "baselines_loaded": ctx.has_baselines(),
        "summary": {"hit": len(hits), "blocked": len(blocked_), "clear": len(clear),
                    "manual_rows_outstanding": len(MANUAL_ROWS)},
        "results": [{**asdict(r), "verdict": verdict(r),
                     "cwe": probe.PRIMITIVE_META.get(r.name, {}).get("cwe", ""),
                     "group": probe.PRIMITIVE_META.get(r.name, {}).get("group", "")}
                    for r in results],
        "manual_rows": {k: {"group": v[0], "recipe": v[1], "kind": v[2]}
                        for k, v in MANUAL_ROWS.items()},
    }
    (d / "sweep.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"\n  -> {d / 'sweep.json'}")
    return 0 if hits else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("url")
    ap.add_argument("--scope")
    ap.add_argument("--slug")
    ap.add_argument("--all", action="store_true", help="every primitive (the default)")
    ap.add_argument("--primitive", action="append", default=[], help="run only these (repeatable)")
    ap.add_argument("--identity", action="append", default=[],
                    help="name=<Cookie header or 'Bearer x'>, repeatable (owner/other/admin/...)")
    ap.add_argument("--opt", action="append", default=[], help="k=v passed to primitives")
    ap.add_argument("--marker", default="probe-9c2f")
    ap.add_argument("--fast", action="store_true", help="skip the timing/volume probes")
    ap.add_argument("--no-browser", action="store_true", dest="no_browser",
                    help="skip the browser checks (they will report NEEDS-BROWSER, not clear)")
    a = ap.parse_args(argv)

    try:
        origin = C.normalize_origin(a.url)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    from urllib.parse import urlsplit
    host = urlsplit(origin).hostname or ""
    if a.scope:
        try:
            sc = S.Scope.load(a.scope)
        except S.ScopeError as e:
            print(f"scope error: {e}", file=sys.stderr)
            return 2
    elif host in ("127.0.0.1", "localhost", "::1"):
        sc = S.Scope.local(host)
    else:
        print(f"refusing to probe {origin} without --scope", file=sys.stderr)
        return S.EXIT_SCOPE_REFUSAL

    slug = a.slug or origin
    wd = C.workdir(slug)
    S.activate(sc, slug, primitive="sweep")

    identities = dict(kv.split("=", 1) for kv in a.identity if "=" in kv)
    opts = dict(kv.split("=", 1) for kv in a.opt if "=" in kv)
    ctx = P.Ctx.load(slug, identities=identities, marker=a.marker, opts=opts)

    if not identities:
        print("note: no --identity given. Every authorization row will report BLOCKED —")
        print("      one account cannot prove IDOR, BFLA, mass assignment or CSRF.")

    only = a.primitive or None
    try:
        out = run(origin, wd, ctx, only=only, skip_slow=a.fast)
        if not a.no_browser and not only:
            for r in run_browser(origin, wd, ctx, sc, slug):
                out["results"].append(r)
                out["by_group"].setdefault("D", []).append(r)
    except S.ScopeViolation as v:
        print(f"SCOPE REFUSAL: {v}\n  nothing further was sent.", file=sys.stderr)
        return S.EXIT_SCOPE_REFUSAL
    return report(origin, out, ctx, wd)


if __name__ == "__main__":
    sys.exit(main())
