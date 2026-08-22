#!/usr/bin/env python3
"""
recon.py — build a live site's attack surface, the black-box replacement for grepping route decorators.

  python web/recon.py https://app.example.com --scope work/<slug>/scope.yml

Stages: passive (robots/sitemap/.well-known) -> link+form crawl with path templating -> JS bundle and
sourcemap mining -> API spec + GraphQL discovery -> fingerprint -> header/cookie/CSP posture ->
BASELINES. Writes work/<slug>/web/{recon,endpoints,forms,baselines,fingerprint,headers}.json plus
web/js/ and web/js/src/.

The baselines matter as much as the endpoints. A live app answers in ways source never does — SPAs
return 200 with an HTML shell for every unknown path, WAFs answer instead of the app — so every later
probe has to show its signal differs from these. Without them the primitives manufacture findings.

Read-only: nothing here sends a payload. The procedure is the `web-recon` skill; this automates the
mechanical parts of it.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit, parse_qsl

ROOT = Path(__file__).resolve().parent.parent
for sub in ("dynamic", "static", "web"):
    sys.path.insert(0, str(ROOT / sub))

import scope as S            # noqa: E402
import _common as C          # noqa: E402
import apispec               # noqa: E402
import fingerprint as FP     # noqa: E402
import jsintel               # noqa: E402

PASSIVE_PATHS = ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
                 "/.well-known/openid-configuration"]
# path segments that are obviously an identifier -> template them so /items/1 and /items/2 collapse
RE_NUMERIC = re.compile(r"^\d+$")
RE_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
RE_HEXID = re.compile(r"^[0-9a-f]{16,}$", re.I)
RE_SLUGID = re.compile(r"^[A-Za-z0-9_-]{20,}$")
SKIP_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot",
            ".mp4", ".webm", ".pdf", ".zip", ".css", ".map")


@dataclass
class Endpoint:
    path: str
    method: str = "GET"
    params: list = field(default_factory=list)
    source: str = "crawl"
    status: int = 0
    content_type: str = ""
    auth_declared: bool | None = None      # from an OpenAPI `security` block, when one exists
    observed_values: list = field(default_factory=list)
    seen_urls: list = field(default_factory=list)


def template_path(path: str) -> tuple[str, list[str]]:
    """/items/42 -> (/items/{id}, ['42']). This collapse is what feeds IDOR enumeration; a flat URL
    list does not, because you cannot tell which segment is the object reference."""
    segs = (path or "/").split("/")
    out, vals = [], []
    for s in segs:
        if RE_NUMERIC.match(s) or RE_UUID.match(s) or RE_HEXID.match(s) or RE_SLUGID.match(s):
            out.append("{id}")
            vals.append(s)
        else:
            out.append(s)
    return "/".join(out) or "/", vals


def _same_origin(a: str, b: str) -> bool:
    ua, ub = urlsplit(a), urlsplit(b)
    return (ua.scheme, ua.hostname, ua.port) == (ub.scheme, ub.hostname, ub.port)


def _clean(url: str) -> str:
    u = urlsplit(url)
    return urlunsplit((u.scheme, u.netloc, u.path, u.query, ""))     # drop the fragment


class Recon:
    def __init__(self, sess: S.ScopedSession, base: str, workdir: Path,
                 depth: int = 2, max_pages: int = 150):
        self.sess = sess
        self.base = base.rstrip("/")
        self.dir = workdir / "web"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.depth = depth
        self.max_pages = max_pages
        self.endpoints: dict[tuple, Endpoint] = {}
        self.forms: list[dict] = []
        self.js_urls: set[str] = set()
        self.hosts_seen: set[str] = set()
        self.notes: list[str] = []
        self.baselines_cache: dict = {}      # soft-404 captured early; discovery is gated on it

    # -------------------------------------------------------------------- helpers ---
    def _record(self, url: str, method: str = "GET", source: str = "crawl",
                status: int = 0, ctype: str = "", params: list | None = None) -> None:
        u = urlsplit(url)
        if u.hostname:
            self.hosts_seen.add(u.hostname)
        tpl, vals = template_path(u.path or "/")
        key = (tpl, method.upper())
        ep = self.endpoints.get(key)
        if ep is None:
            ep = Endpoint(path=tpl, method=method.upper(), source=source)
            self.endpoints[key] = ep
        if status:
            ep.status = status
        if ctype:
            ep.content_type = ctype.split(";")[0]
        for v in vals:
            if v not in ep.observed_values:
                ep.observed_values.append(v)
        for name, _ in parse_qsl(u.query):
            if not any(p["name"] == name for p in ep.params):
                ep.params.append({"name": name, "in": "query", "required": False})
        for p in (params or []):
            if not any(q["name"] == p["name"] and q.get("in") == p.get("in") for q in ep.params):
                ep.params.append(p)
        if len(ep.seen_urls) < 3 and url not in ep.seen_urls:
            ep.seen_urls.append(url)

    def _get(self, url: str):
        try:
            return self.sess.get(url)
        except S.ScopeViolation:
            raise
        except Exception as e:                            # noqa: BLE001
            self.notes.append(f"{url}: {type(e).__name__}")
            return None

    # ------------------------------------------------------------------- 1 passive ---
    def passive(self) -> dict:
        out = {}
        for p in PASSIVE_PATHS:
            r = self._get(self.base + p)
            if r is None or r.status_code != 200:
                continue
            out[p] = r.text[:8000]
            (self.dir / p.strip("/").replace("/", "_")).write_text(r.text, encoding="utf-8")
            if p == "/robots.txt":
                # Disallow entries are a hint list of interesting paths, never a boundary
                for m in re.finditer(r"(?im)^\s*(?:dis)?allow:\s*(\S+)", r.text):
                    hint = m.group(1)
                    if hint.startswith("/") and "*" not in hint:
                        self._record(self.base + hint, source="robots")
            if p == "/sitemap.xml":
                for m in re.finditer(r"<loc>\s*([^<\s]+)\s*</loc>", r.text):
                    if _same_origin(m.group(1), self.base):
                        self._record(m.group(1), source="sitemap")
        return out

    # --------------------------------------------------------------------- 2 crawl ---
    def crawl(self) -> None:
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            self.notes.append("beautifulsoup4 missing — crawl limited to regex link extraction")
            BeautifulSoup = None                          # noqa: N806

        seen: set[str] = set()
        q: deque = deque([(self.base + "/", 0)])
        pages = 0
        while q and pages < self.max_pages:
            url, d = q.popleft()
            url = _clean(url)
            if url in seen or d > self.depth:
                continue
            seen.add(url)
            if urlsplit(url).path.lower().endswith(SKIP_EXT):
                continue
            r = self._get(url)
            if r is None:
                continue
            pages += 1
            ctype = r.headers.get("Content-Type", "")
            self._record(url, "GET", "crawl", r.status_code, ctype)
            if "html" not in ctype.lower():
                continue

            links, scripts = [], []
            if BeautifulSoup:
                soup = BeautifulSoup(r.text, "html.parser")
                links = [a.get("href") for a in soup.find_all(["a", "link"]) if a.get("href")]
                scripts = [s.get("src") for s in soup.find_all("script") if s.get("src")]
                for f in soup.find_all("form"):
                    action = urljoin(url, f.get("action") or url)
                    method = (f.get("method") or "GET").upper()
                    inputs = []
                    for i in f.find_all(["input", "select", "textarea"]):
                        n = i.get("name")
                        if n:
                            inputs.append({"name": n, "in": "body",
                                           "type": i.get("type", "text"),
                                           "hidden": i.get("type") == "hidden"})
                    if _same_origin(action, self.base):
                        self.forms.append({"action": urlsplit(action).path, "method": method,
                                           "inputs": inputs, "page": urlsplit(url).path,
                                           # a form with no token-shaped hidden input is the CSRF lead
                                           "csrf_field": next(
                                               (i["name"] for i in inputs
                                                if re.search(r"(?i)csrf|xsrf|_token|authenticity", i["name"])), "")})
                        self._record(action, method, "form", params=inputs)
            else:
                links = re.findall(r'href=["\']([^"\']+)', r.text)
                scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)', r.text)

            for s in scripts:
                su = urljoin(url, s)
                if _same_origin(su, self.base) and su.split("?")[0].endswith(".js"):
                    self.js_urls.add(su)
            for href in links:
                if not href or href.startswith(("mailto:", "tel:", "javascript:", "#", "data:")):
                    continue
                nxt = urljoin(url, href)
                if _same_origin(nxt, self.base):
                    q.append((nxt, d + 1))
                else:
                    h = urlsplit(nxt).hostname
                    if h:
                        self.hosts_seen.add(h)

    # ----------------------------------------------------------------- 2b discover ---
    # Anything the UI never links to is invisible to a crawl — and that is exactly where the
    # under-tested handlers live (admin, debug, import/export, webhook receivers, old versions).
    # Every candidate is checked against the soft-404 baseline first, so a target that answers 200
    # for everything cannot turn this into 200 phantom endpoints.
    COMMON_PATHS = [
        # auth & identity
        "/login", "/api/login", "/api/auth/login", "/signin", "/api/session", "/api/token",
        "/logout", "/api/logout", "/register", "/api/register", "/api/me", "/api/user",
        "/api/password/reset", "/api/password/forgot", "/forgot-password", "/reset-password",
        "/api/mfa/verify", "/oauth/authorize", "/oauth/token", "/api/refresh",
        # data & objects
        "/api/users", "/api/items", "/api/orders", "/api/files", "/api/documents",
        "/api/search", "/search", "/api/find", "/api/query", "/api/list",
        # state mutation
        "/api/settings", "/api/config", "/api/preferences", "/api/profile", "/api/account",
        "/api/update", "/api/import", "/api/export", "/api/upload", "/upload", "/api/webhook",
        # rendering / redirect / templating
        "/go", "/redirect", "/api/redirect", "/preview", "/api/preview", "/render", "/proxy",
        "/api/proxy", "/fetch", "/api/fetch", "/api/render", "/download", "/api/download",
        # admin & debug
        "/admin", "/api/admin", "/api/admin/users", "/api/internal", "/debug", "/api/debug",
        "/actuator", "/actuator/env", "/actuator/health", "/metrics", "/api/status", "/health",
        "/server-status", "/.env", "/config.json", "/api/version",
        # api surfaces
        "/graphql", "/api/graphql", "/graphiql", "/ws", "/socket.io/", "/api/stream", "/events",
        # versioned twins — the fix often landed on v2 while v1 stayed routed
        "/api/v1/users", "/api/v1/items", "/api/v2/users", "/api/v2/items", "/api/internal/audit-log",
    ]

    def discover(self) -> int:
        base404 = (self.baselines_cache or {}).get("soft_404") or {}
        found = 0
        for p in self.COMMON_PATHS:
            if (p, "GET") in self.endpoints:
                continue
            r = self._get(self.base + p)
            if r is None:
                continue
            # a real endpoint differs from the soft-404 shell; anything matching it is the shell
            if base404:
                if r.status_code == base404.get("status") and _shape(r.text or "") == base404.get("fingerprint"):
                    continue
            elif r.status_code == 404:
                continue
            if r.status_code in (400, 401, 403, 405, 422, 500):
                # an error that ISN'T the 404 shell means the route exists and rejected us —
                # 401/403 are the interesting ones, they mark the authorization surface
                self._record(self.base + p, "GET", "discovery", r.status_code,
                             r.headers.get("Content-Type", ""))
                found += 1
                continue
            if r.status_code < 400:
                self._record(self.base + p, "GET", "discovery", r.status_code,
                             r.headers.get("Content-Type", ""))
                found += 1
        return found

    def probe_methods(self, limit: int = 25) -> int:
        """Which verbs does each endpoint actually accept? OPTIONS when it answers, else a cheap
        probe. Knowing POST/PATCH exist is what makes the mutation classes testable at all."""
        added = 0
        for ep in list(self.endpoints.values())[:limit]:
            if ep.method != "GET":
                continue
            url = self.base + ep.path.replace("{id}", (ep.observed_values or ["1"])[0])
            try:
                o = self.sess.options(url)
            except Exception:                          # noqa: BLE001
                continue
            allow = (o.headers.get("Allow") or o.headers.get("Access-Control-Allow-Methods") or "")
            for m in [x.strip().upper() for x in allow.split(",") if x.strip()]:
                if m in ("POST", "PUT", "PATCH", "DELETE") and (ep.path, m) not in self.endpoints:
                    self._record(url, m, "options-allow")
                    added += 1
        return added

    # ---------------------------------------------------------------------- 3 js ---
    def bundles(self) -> list[dict]:
        # inline scripts referenced only from the JS itself (chunk maps) aren't followed here; the
        # entry bundles are where the endpoint strings live
        out = []
        for u in sorted(self.js_urls)[:12]:
            intel = jsintel.analyze_bundle(self.sess, u, self.dir / "js")
            for e in intel.endpoints:
                self._record(urljoin(self.base, e["path"]), e.get("method", "GET"), "jsbundle")
            out.append(intel.to_dict())
        return out

    # -------------------------------------------------------------------- 4 specs ---
    def specs(self) -> dict:
        spec = apispec.discover(self.sess, self.base)
        schema = spec.pop("_graphql_schema", None)
        if schema:
            (self.dir / "graphql-schema.json").write_text(
                json.dumps(schema, indent=2), encoding="utf-8")
        if spec.get("openapi"):
            (self.dir / "openapi.json").write_text(
                json.dumps(spec["openapi"], indent=2), encoding="utf-8")
        for e in spec.get("endpoints", []):
            key = (e["path"], e["method"])
            ep = self.endpoints.get(key)
            if ep is None:
                ep = Endpoint(path=e["path"], method=e["method"], source=e["source"])
                self.endpoints[key] = ep
            ep.auth_declared = e.get("auth_declared")
            for p in e.get("params", []):
                if not any(q["name"] == p["name"] for q in ep.params):
                    ep.params.append(p)
        spec.pop("openapi", None)                          # the doc is on disk; don't inline it
        spec.pop("endpoints", None)
        return spec

    # ---------------------------------------------------------------- 5 baselines ---
    def baselines(self, auth_cookie: str = "") -> dict:
        """The controls every later probe compares against. Skipping this is how a black-box hunt
        produces a page of false positives."""
        marker = "definitely-not-a-real-path-9c2f"
        out: dict = {}

        def snap(label, url, **kw):
            r = self._get(url) if not kw else None
            if kw:
                try:
                    r = self.sess.get(url, **kw)
                except Exception:                          # noqa: BLE001
                    r = None
            if r is None:
                return
            body = r.text or ""
            out[label] = {
                "url": url, "status": r.status_code, "length": len(body),
                "content_type": (r.headers.get("Content-Type") or "").split(";")[0],
                "fingerprint": _shape(body),
                "excerpt": body[:300],
            }

        snap("soft_404", f"{self.base}/{marker}")
        # pick a real endpoint for the parameter and auth baselines, so the comparison is meaningful
        real = next((e for e in self.endpoints.values()
                     if e.method == "GET" and 200 <= e.status < 300 and "{id}" not in e.path), None)
        if real:
            u = self.base + real.path
            snap("unknown_param", f"{u}?{marker}=1")
            snap("unauthenticated", u)
            if auth_cookie:
                snap("owner", u, headers={"Cookie": auth_cookie})
            out["_endpoint_used"] = real.path

        if out.get("soft_404", {}).get("status", 404) == 200:
            self.notes.append(
                "SOFT-404: an unknown path returns HTTP 200 — status alone proves nothing on this "
                "target. Every probe must diff against the soft_404 fingerprint.")
        return out

    # ------------------------------------------------------------------ 6 posture ---
    def posture(self, path: str = "/", auth_cookie: str = "") -> dict:
        kw = {"headers": {"Cookie": auth_cookie}} if auth_cookie else {}
        try:
            r = self.sess.get(self.base + path, **kw)
        except Exception as e:                             # noqa: BLE001
            return {"error": f"{type(e).__name__}: {e}"}
        headers = dict(r.headers)
        # requests folds repeated Set-Cookie into one comma-joined value; split on the boundary
        raw_sc = headers.get("Set-Cookie", "")
        cookies = FP.parse_cookies(re.split(r",\s*(?=[A-Za-z0-9_\-]+=)", raw_sc) if raw_sc else [])
        return {
            "path": path,
            "authenticated": bool(auth_cookie),
            "fingerprint": FP.fingerprint(headers, r.text or ""),
            "headers": FP.analyze_headers(headers, authenticated=bool(auth_cookie)),
            "cookies": cookies,
        }

    # ---------------------------------------------------------------------- run ---
    def run(self, auth_cookie: str = "", posture_path: str = "/", discover: bool = True) -> dict:
        started = time.time()
        passive = self.passive()
        self.crawl()
        # The soft-404 shape has to exist before content discovery, or a target that answers 200 for
        # every path turns the wordlist into a hundred phantom endpoints.
        self.baselines_cache = self.baselines(auth_cookie)
        discovered = self.discover() if discover else 0
        methods_found = self.probe_methods() if discover else 0
        bundles = self.bundles()
        specs = self.specs()
        post = self.posture(posture_path, auth_cookie)
        base = self.baselines(auth_cookie)          # re-take: discovery may have found a better endpoint

        eps = [{"path": e.path, "method": e.method, "params": e.params, "source": e.source,
                "status": e.status, "content_type": e.content_type,
                "auth_declared": e.auth_declared, "observed_values": e.observed_values[:5],
                "seen_urls": e.seen_urls}
               for e in sorted(self.endpoints.values(), key=lambda x: (x.path, x.method))]

        (self.dir / "endpoints.json").write_text(json.dumps(eps, indent=2), encoding="utf-8")
        (self.dir / "forms.json").write_text(json.dumps(self.forms, indent=2), encoding="utf-8")
        (self.dir / "baselines.json").write_text(json.dumps(base, indent=2), encoding="utf-8")
        (self.dir / "fingerprint.json").write_text(
            json.dumps(post.get("fingerprint", {}), indent=2), encoding="utf-8")
        (self.dir / "headers.json").write_text(json.dumps(post, indent=2), encoding="utf-8")

        summary = {
            "base": self.base,
            "elapsed_s": round(time.time() - started, 1),
            "counts": {
                "endpoints": len(eps),
                "methods": len({e["method"] for e in eps}),
                "params": sum(len(e["params"]) for e in eps),
                "forms": len(self.forms),
                "js_bundles": len(bundles),
                "hosts_seen": len(self.hosts_seen),
                "discovered": discovered,
                "methods_from_options": methods_found,
            },
            "js": jsintel.summarize(bundles),
            "specs": specs,
            "passive": sorted(passive),
            "posture_issues": post.get("headers", {}).get("issues", []),
            "hosts_seen": sorted(self.hosts_seen),
            "notes": self.notes,
        }
        (self.dir / "recon.json").write_text(
            json.dumps({"summary": summary, "bundles": bundles, "posture": post,
                        "baselines": base}, indent=2), encoding="utf-8")
        return summary


def _shape(body: str) -> str:
    """A cheap structural fingerprint that survives dynamic content (timestamps, csrf tokens) — used
    to tell a real response from a soft-404 that merely has a different length."""
    import hashlib
    skeleton = re.sub(r"[0-9a-f]{8,}|\d+", "#", (body or "")[:4000])
    skeleton = re.sub(r"\s+", " ", skeleton)
    return hashlib.sha256(skeleton.encode("utf-8", "replace")).hexdigest()[:16]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("url", help="target origin, e.g. https://app.example.com")
    ap.add_argument("--scope", help="scope.yml (required for a non-loopback host)")
    ap.add_argument("--slug", help="workdir hint; defaults to the origin")
    ap.add_argument("--depth", type=int, default=2)
    ap.add_argument("--max-pages", type=int, default=150)
    ap.add_argument("--auth-cookie", default="", help="Cookie header for the authenticated baselines")
    ap.add_argument("--posture-path", default="/",
                    help="the SENSITIVE authenticated path to read headers from (not the root)")
    a = ap.parse_args(argv)

    try:
        origin = C.normalize_origin(a.url)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

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
        print(f"refusing to recon {origin} without --scope — a live host needs a scope.yml naming "
              f"the program that authorizes it (start from scope.example.yml)", file=sys.stderr)
        return S.EXIT_SCOPE_REFUSAL

    slug = a.slug or origin
    wd = C.workdir(slug)
    sess = S.ScopedSession(sc, slug, identity="anon", workdir=wd, primitive="recon")

    try:
        summary = Recon(sess, origin, wd, depth=a.depth, max_pages=a.max_pages).run(
            auth_cookie=a.auth_cookie, posture_path=a.posture_path)
    except S.ScopeViolation as v:
        print(f"SCOPE REFUSAL: {v}\n  nothing was sent.", file=sys.stderr)
        return S.EXIT_SCOPE_REFUSAL

    c = summary["counts"]
    print(f"\nrecon {origin} -> {wd / 'web'}")
    print(f"  endpoints {c['endpoints']} · params {c['params']} · methods {c['methods']} · "
          f"forms {c['forms']} · bundles {c['js_bundles']}")
    j = summary["js"]
    print(f"  js: {j['sources_recovered']} sources recovered from sourcemaps · "
          f"{j['role_checks']} client-side role checks · {j['dom_pairs']} DOM source->sink pairs · "
          f"{j['postmessage_unchecked']} unchecked postMessage handlers · {j['secrets']} secret hits")
    if j["sources_recovered"]:
        print(f"  -> GREY-BOX: hunt scan {wd / 'web' / 'js' / 'src'}")
    if summary["specs"].get("openapi_path"):
        print(f"  openapi: {summary['specs']['openapi_path']}")
    if summary["specs"].get("graphql"):
        print(f"  graphql: {summary['specs']['graphql']}")
    for i in summary["posture_issues"][:8]:
        print(f"  ! {i}")
    for n in summary["notes"]:
        print(f"  note: {n}")
    print(f"\n  transcript: {sess.transcript_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
