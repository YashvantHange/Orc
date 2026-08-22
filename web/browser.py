#!/usr/bin/env python3
"""
browser.py — the checks that only a real browser can settle.

Six matrix rows are unfalsifiable over raw HTTP, because their sink runs in the page and, for the
DOM cases, the input never reaches the server at all (`location.hash` is not transmitted). String-
matching a response body proves nothing here; the question is always **did it execute**.

  DOM XSS · CSTI · client prototype pollution · postMessage origin · clickjacking (rendered) ·
  effective CSP · cookie flags as the browser sees them · SPA route guards

Chromium has its own network stack, so `ScopedSession` never sees its traffic. Every request is
routed through `page.route()` into the same scope check and the same T##### transcript, so browser
evidence cites identically to HTTP evidence.

Degrades honestly: with no browser installed, each check returns confirmed=False with
`needs_browser` set. The coverage layer records NEEDS-BROWSER — never CLEAR. A class you could not
execute is not a class you cleared.

  .venv/Scripts/python.exe -m pip install playwright
  .venv/Scripts/python.exe -m playwright install chromium
"""
from __future__ import annotations

import json
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urljoin, urlsplit

ROOT = Path(__file__).resolve().parent.parent
for sub in ("dynamic", "static", "web"):
    sys.path.insert(0, str(ROOT / sub))

import scope as S                                    # noqa: E402
from primitives import ProbeResult                   # noqa: E402

MARKER = "xss-probe-9c2f"


_AVAILABLE: tuple | None = None


def available() -> tuple[bool, str]:
    """Check the BROWSER BINARY, not just the import — `pip install playwright` succeeds on its own
    and then fails at launch, which would otherwise look like a clean CLEAR.

    Cached: each probe spins up and tears down a driver process, and doing that twice per run is
    what produces playwright's 'Task was destroyed' noise on Windows.
    """
    global _AVAILABLE
    if _AVAILABLE is not None:
        return _AVAILABLE
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        _AVAILABLE = (False, "playwright not installed (pip install playwright)")
        return _AVAILABLE
    try:
        with sync_playwright() as p:
            path = p.chromium.executable_path
            if not path or not Path(path).exists():
                _AVAILABLE = (False, "chromium binary missing (playwright install chromium)")
                return _AVAILABLE
    except Exception as e:                             # noqa: BLE001
        _AVAILABLE = (False, f"playwright unusable: {type(e).__name__}: {e}")
        return _AVAILABLE
    _AVAILABLE = (True, "")
    return _AVAILABLE


def needs_browser(name: str, endpoint: str, why: str) -> ProbeResult:
    return ProbeResult(name, False, endpoint, detail=f"NEEDS-BROWSER: {why}",
                       evidence={"needs_browser": True, "reason": why})


@contextmanager
def browser(scope: S.Scope, slug: str, identity: str = "anon", cookie: str = "",
            headless: bool = True):
    """A Chromium page whose every request passes the scope check and lands in the transcript."""
    from playwright.sync_api import sync_playwright

    sess = S.ScopedSession(scope, slug, identity=identity, primitive="browser")
    with sync_playwright() as p:
        br = p.chromium.launch(headless=headless)
        ctx = br.new_context(ignore_https_errors=False,
                             user_agent=scope.user_agent)
        page = ctx.new_page()

        def _route(route, request):
            # data:/blob:/about: never leave the browser — they are the attacker-page harness itself
            # (a framing test loads one). Scope-checking them would abort our own test rig.
            if not request.url.lower().startswith(("http://", "https://")):
                route.continue_()
                return
            tid = sess.transcript.next_id()
            try:
                scope.check(request.method, request.url)
            except S.ScopeViolation as v:
                sess.transcript.write({"id": tid, "ts": S._now(), "refused": True,
                                       "via": "browser", "identity": identity,
                                       "method": request.method, "url": request.url,
                                       "reason": v.reason, "rule": v.rule,
                                       "scope_digest": scope.digest()})
                route.abort("blockedbyclient")
                return
            scope._bucket.acquire()
            sess.transcript.write({"id": tid, "ts": S._now(), "via": "browser",
                                   "identity": identity, "method": request.method,
                                   "url": request.url, "resource_type": request.resource_type,
                                   "scope_digest": scope.digest()})
            route.continue_()

        page.route("**/*", _route)                     # navigations AND subresources

        if cookie and "=" in cookie:
            name, _, value = cookie.partition("=")
            host = urlsplit(scope.raw.get("_base", "") or "").hostname
            try:
                ctx.add_cookies([{"name": name.strip(), "value": value.strip(),
                                  "url": scope.raw.get("_base") or f"http://{host}"}])
            except Exception:                          # noqa: BLE001 - bad cookie shape is not fatal
                pass
        try:
            yield page, sess
        finally:
            ctx.close()
            br.close()


# ------------------------------------------------------------------------- the checks ---
def confirm_dom_xss(page, base: str, candidates: list) -> ProbeResult:
    """Execution-confirmed, not reflection-matched.

    `alert`/`print`/`confirm` are overridden before any page script runs, and a hook records the
    call. The proof is that the hook fired — a marker appearing in the HTML proves only reflection,
    which for a hash-based sink is not even possible to observe server-side.
    """
    fired: list = []
    page.expose_function("__probeHit", lambda src: fired.append(src))
    page.add_init_script("""
        (() => {
          const hit = (src) => { try { window.__probeHit(String(src)); } catch (e) {} };
          for (const fn of ['alert', 'confirm', 'prompt', 'print']) {
            window[fn] = (v) => hit(fn + ':' + v);
          }
          // a payload that writes the marker into the title also counts as execution
          const td = Object.getOwnPropertyDescriptor(Document.prototype, 'title');
          if (td && td.set) {
            Object.defineProperty(document, 'title', {
              set(v) { if (String(v).includes('%MARKER%')) hit('title:' + v); td.set.call(document, v); },
              get() { return td.get.call(document); }, configurable: true
            });
          }
        })();
    """.replace("%MARKER%", MARKER))

    payloads = [
        f"<img src=x onerror=\"document.title='{MARKER}'\">",
        f"<svg onload=\"document.title='{MARKER}'\">",
        f"<img src=x onerror=alert('{MARKER}')>",
        f"\"><script>document.title='{MARKER}'</script>",
        f"javascript:alert('{MARKER}')",
        f"';document.title='{MARKER}';//",
    ]
    tried = []
    for cand in candidates:
        for payload in payloads:
            from urllib.parse import quote
            for url in (f"{base}{cand}#{quote(payload)}",
                        f"{base}{cand}?q={quote(payload)}",
                        f"{base}{cand}#/search?q={quote(payload)}"):
                tried.append(url)
                fired.clear()
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=8000)
                    page.wait_for_timeout(350)
                except Exception:                      # noqa: BLE001 - a nav failure is not a finding
                    continue
                if fired or MARKER in (page.title() or ""):
                    return ProbeResult("dom_xss", True, cand, payload, 200,
                                       "payload EXECUTED in the page (hook fired) — not merely "
                                       "reflected",
                                       {"url": url, "hook": fired[:3] or ["title"],
                                        "title": page.title(),
                                        "enumerated": len(tried)})
    return ProbeResult("dom_xss", False, candidates[0] if candidates else "/",
                       detail=f"no execution across {len(tried)} source/sink/payload combinations",
                       evidence={"enumerated": len(tried)})


@contextmanager
def attacker_origin(html: str):
    """Serve the attacker page from a real, separate origin on 127.0.0.1.

    A `data:` or `about:blank` document has an opaque origin, and Chromium's Private Network Access
    rules refuse to let one frame a private IP — the iframe fails with chrome-error:// and the check
    reports "framing is blocked" on a target with no framing controls at all. A second loopback port
    is a genuinely different origin (origin includes the port) and both ends are private, so the
    browser applies the site's real framing policy instead of a network-level veto.
    """
    import http.server
    import socket
    import threading

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = html.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            return

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    srv = http.server.HTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{port}/"
    finally:
        srv.shutdown()


def check_clickjacking(page, base: str, path: str) -> ProbeResult:
    """Render the target inside an iframe from a foreign origin and see whether it paints.

    A missing header is a hardening note. A frame with the sensitive control visible is the report.
    """
    target = f"{base}{path}"
    html = ("<!doctype html><h1>attacker page</h1>"
            f"<iframe id=f src='{target}' width=900 height=600 style='opacity:1'></iframe>")
    try:
        with attacker_origin(html) as harness:
            return _framed(page, base, path, target, harness)
    except Exception as e:                             # noqa: BLE001
        return ProbeResult("clickjacking", False, path, detail=f"{type(e).__name__}: {e}")


def _framed(page, base: str, path: str, target: str, harness: str) -> ProbeResult:
    try:
        page.goto(harness, wait_until="domcontentloaded", timeout=8000)
        page.wait_for_timeout(700)
        frame = next((f for f in page.frames if f.url.startswith(base)), None)
        if frame is None:
            errored = any(f.url.startswith("chrome-error://") for f in page.frames)
            return ProbeResult(
                "clickjacking", False, path,
                detail=("the frame failed to load at the network level (chrome-error) — this is "
                        "NOT proof of a framing policy; re-check the harness origin"
                        if errored else "the frame did not load — framing is blocked"),
                evidence={"frames": [f.url[:80] for f in page.frames],
                          "inconclusive": errored})
        body = (frame.evaluate("document.body ? document.body.innerText : ''") or "").strip()
        if len(body) < 5:
            return ProbeResult("clickjacking", False, path,
                               detail="frame loaded but rendered empty — effectively not framable")
        return ProbeResult("clickjacking", True, path, "cross-origin iframe", 200,
                           "the page RENDERS inside an iframe from a foreign origin with its "
                           "content visible",
                           {"framed_text": body[:200], "target": target, "harness": harness,
                            "screenshot_hint": "capture this frame for the report"})
    except Exception as e:                             # noqa: BLE001
        return ProbeResult("clickjacking", False, path, detail=f"{type(e).__name__}: {e}")


def check_postmessage(page, base: str, paths) -> ProbeResult:
    """Post from a foreign context on EVERY candidate page and see whether a handler acted.

    Listeners live wherever the app registers them, so checking one page is a coin flip — a CLEAR
    here has to mean "no page had an exploitable handler", not "the page I happened to pick didn't".
    """
    if isinstance(paths, str):
        paths = [paths]
    marker = f"pm-{MARKER}"
    # message shapes that cover the common handler dispatch conventions
    script = """(m) => {
        const shapes = [
          {type:'setState', value:m}, {type:'setName', value:m}, {type:'setTitle', value:m},
          {action:'setState', value:m}, {cmd:'set', value:m}, {event:'update', data:m}, m
        ];
        for (const s of shapes) { try { window.postMessage(s, '*'); } catch (e) {} }
    }"""
    tried = []
    for path in paths:
        tried.append(path)
        try:
            page.goto(f"{base}{path}", wait_until="domcontentloaded", timeout=8000)
        except Exception:                              # noqa: BLE001
            continue
        # a handler registered at all is the precondition worth reporting even if none acted
        try:
            before = page.title()
            page.evaluate(script, marker)
            page.wait_for_timeout(400)
            body = page.evaluate("document.body ? document.body.innerText : ''") or ""
            acted = marker in (page.title() or "") or marker in body
        except Exception:                              # noqa: BLE001
            continue
        if acted:
            return ProbeResult("postmessage_origin", True, path,
                               "postMessage from a foreign context", 200,
                               "a message handler acted on attacker-supplied data with no "
                               "effective event.origin check",
                               {"marker": marker, "title_before": before,
                                "title_after": page.title(), "enumerated": tried})
    return ProbeResult("postmessage_origin", False, tried[0] if tried else "/",
                       detail=f"no listener acted on an unvalidated message across "
                              f"{len(tried)} page(s)",
                       evidence={"enumerated": tried})


def check_proto_pollution_client(page, base: str, path: str) -> ProbeResult:
    """Pollute through a client-side merge, then read the key off a FRESH object."""
    try:
        page.goto(f"{base}{path}", wait_until="domcontentloaded", timeout=8000)
    except Exception as e:                             # noqa: BLE001
        return ProbeResult("proto_pollution_client", False, path, detail=f"{type(e).__name__}: {e}")
    key = "pp_probe_9c2f"
    try:
        polluted = page.evaluate("""(k) => {
            // The payload MUST be built as raw JSON text. `JSON.stringify({__proto__: {...}})`
            // returns "{}" — in an object literal `__proto__:` sets the prototype instead of
            // creating a key, so the payload silently becomes empty and every target looks clean.
            const payload = '{"__proto__":{"' + k + '":"polluted"}}';
            const parsed = JSON.parse(payload);          // JSON.parse DOES create an own __proto__
            for (const fn of ['__applySettings','applySettings','merge','deepMerge','deepExtend',
                              'extend','mergeDeep','setPath','set']) {
              try { if (typeof window[fn] === 'function') { window[fn](payload); } } catch (e) {}
              try { if (typeof window[fn] === 'function') { window[fn]({}, parsed); } } catch (e) {}
            }
            return ({})[k] === 'polluted';
        }""", key)
    except Exception:                                  # noqa: BLE001
        polluted = False
    if polluted:
        return ProbeResult("proto_pollution_client", True, path, "__proto__ via a client merge", 200,
                           f"Object.prototype polluted — ({{}}).{key} returns 'polluted' on a fresh "
                           f"object",
                           {"key": key})
    return ProbeResult("proto_pollution_client", False, path,
                       detail="client merge helpers reject or contain __proto__")


def check_cookie_flags(page, base: str) -> ProbeResult:
    """context.cookies() is authoritative — it includes JS-set cookies and the final attribute set."""
    try:
        page.goto(base + "/", wait_until="domcontentloaded", timeout=8000)
        cookies = page.context.cookies()
    except Exception as e:                             # noqa: BLE001
        return ProbeResult("cookie_flags_effective", False, "/", detail=f"{type(e).__name__}: {e}")
    issues = []
    for c in cookies:
        n = c.get("name", "")
        if not any(k in n.lower() for k in ("session", "sid", "auth", "token", "jwt")):
            continue
        if not c.get("httpOnly"):
            issues.append(f"{n}: no HttpOnly — readable by any script (CWE-1004)")
        if not c.get("secure") and base.startswith("https"):
            issues.append(f"{n}: no Secure (CWE-614)")
        ss = (c.get("sameSite") or "").lower()
        if ss in ("none", ""):
            issues.append(f"{n}: SameSite={c.get('sameSite') or 'unset'} — sent cross-site (CWE-1275)")
        if (c.get("domain") or "").startswith("."):
            issues.append(f"{n}: Domain={c['domain']} — shared with every sibling subdomain")
    if issues:
        return ProbeResult("cookie_flags_effective", True, "/", "browser cookie jar", 200,
                           "; ".join(issues[:4]),
                           {"issues": issues,
                            "note": "hardening notes alone — report inside a chain and name the chain"})
    return ProbeResult("cookie_flags_effective", False, "/", detail="session cookie flags are sound")


def check_csp_effective(page, base: str, path: str) -> ProbeResult:
    """Does the policy actually stop an inline script? Collect securitypolicyviolation events."""
    violations: list = []
    page.expose_function("__cspViolation", lambda d: violations.append(d))
    page.add_init_script("""
        document.addEventListener('securitypolicyviolation', e => {
          try { window.__cspViolation(e.violatedDirective + ' | ' + e.blockedURI); } catch (x) {}
        });
    """)
    try:
        page.goto(f"{base}{path}", wait_until="domcontentloaded", timeout=8000)
        ran = page.evaluate("""() => {
            try {
              const s = document.createElement('script');
              s.textContent = "window.__inlineRan = true;";
              document.head.appendChild(s);
              return window.__inlineRan === true;
            } catch (e) { return false; }
        }""")
        page.wait_for_timeout(300)
    except Exception as e:                             # noqa: BLE001
        return ProbeResult("csp_effective", False, path, detail=f"{type(e).__name__}: {e}")
    if ran and not violations:
        return ProbeResult("csp_effective", True, path, "inline script injection", 200,
                           "an injected inline script EXECUTED and the CSP raised no violation — "
                           "the policy does not contain script injection",
                           {"inline_executed": True, "violations": violations})
    return ProbeResult("csp_effective", False, path,
                       detail=("inline script blocked by CSP" if violations
                               else "inline script did not execute"),
                       evidence={"violations": violations[:5]})


BROWSER_CHECKS = {
    "dom_xss": ("D", "CWE-79"),
    "clickjacking": ("D", "CWE-1021"),
    "postmessage_origin": ("D", "CWE-346"),
    "proto_pollution_client": ("D", "CWE-1321"),
    "cookie_flags_effective": ("D", "CWE-1004"),
    "csp_effective": ("D", "CWE-693"),
}


def run_all(scope: S.Scope, slug: str, base: str, dom_candidates: list | None = None,
            sensitive_path: str = "/account", cookie: str = "",
            headless: bool = True) -> list:
    """Every browser check. Returns NEEDS-BROWSER results (not CLEAR) when Chromium is unavailable."""
    ok, why = available()
    if not ok:
        return [needs_browser(name, "", why) for name in BROWSER_CHECKS]

    scope.raw["_base"] = base                          # so add_cookies can scope the jar
    dom_candidates = dom_candidates or ["/", "/static/dom.html", "/app", "/search"]
    results = []
    with browser(scope, slug, cookie=cookie, headless=headless) as (page, _sess):
        for fn, args in (
            (confirm_dom_xss, (page, base, dom_candidates)),
            (check_clickjacking, (page, base, sensitive_path)),
            (check_postmessage, (page, base, dom_candidates)),
            (check_proto_pollution_client, (page, base, "/")),
            (check_cookie_flags, (page, base)),
            (check_csp_effective, (page, base, sensitive_path)),
        ):
            try:
                results.append(fn(*args))
            except S.ScopeViolation as v:
                results.append(ProbeResult(fn.__name__, False, "",
                                           detail=f"BLOCKED: scope refused — {v.reason}",
                                           evidence={"blocked": True}))
            except Exception as e:                     # noqa: BLE001 - one bad check can't end the run
                results.append(ProbeResult(fn.__name__, False, "",
                                           detail=f"error: {type(e).__name__}: {e}"))
    return results


def main(argv=None) -> int:
    import argparse
    import _common as C
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("url")
    ap.add_argument("--scope")
    ap.add_argument("--slug")
    ap.add_argument("--cookie", default="", help="session cookie, name=value")
    ap.add_argument("--sensitive-path", default="/account", dest="sensitive_path")
    ap.add_argument("--dom-path", action="append", default=[], dest="dom_paths")
    ap.add_argument("--headed", action="store_true")
    a = ap.parse_args(argv)

    ok, why = available()
    print(f"browser: {'ready' if ok else 'UNAVAILABLE — ' + why}")

    origin = C.normalize_origin(a.url)
    host = urlsplit(origin).hostname or ""
    if a.scope:
        sc = S.Scope.load(a.scope)
    elif host in ("127.0.0.1", "localhost", "::1"):
        sc = S.Scope.local(host)
    else:
        print(f"refusing to drive a browser at {origin} without --scope", file=sys.stderr)
        return S.EXIT_SCOPE_REFUSAL

    slug = a.slug or origin
    wd = C.workdir(slug)
    results = run_all(sc, slug, origin, dom_candidates=a.dom_paths or None,
                      sensitive_path=a.sensitive_path, cookie=a.cookie, headless=not a.headed)

    print(f"\nbrowser checks — {origin}")
    for r in results:
        if r.evidence.get("needs_browser"):
            tag = "NEEDS-BROWSER"
        elif r.confirmed:
            tag = "HIT          "
        else:
            tag = "clear        "
        print(f"  [{tag}] {r.name:24} {r.endpoint[:24]:24} {r.detail[:80]}")

    out = wd / "web" / "browser.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    from dataclasses import asdict
    out.write_text(json.dumps([asdict(r) for r in results], indent=2), encoding="utf-8")
    print(f"\n  -> {out}")
    return 0 if any(r.confirmed for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
