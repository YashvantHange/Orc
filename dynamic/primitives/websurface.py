#!/usr/bin/env python3
"""Web-surface primitives — open redirect, host header, CSRF, clickjacking headers, CORS variants,
cache poisoning, cache deception, request smuggling.

Three of these touch shared state that other people's requests also read. They are DETECTION ONLY
and each is scoped so that only a URL we alone request can be affected. See disclosure-ethics.
"""
from __future__ import annotations

import random
import re
import time
from urllib.parse import urlsplit

from . import (Ctx, ProbeResult, TIMEOUT, blocked, median, primitive, requests, send, shape, timed)

EVIL = "evil.example"


@primitive("open_redirect", default_param="next", group="C", cwe="CWE-601")
def open_redirect(base: str, endpoint: str, param: str = "next", ctx: Ctx | None = None) -> ProbeResult:
    """A Location header pointing off-origin. Ladder covers the parsers that "validate" by prefix."""
    ctx = ctx or Ctx()
    payloads = [
        f"https://{EVIL}", f"//{EVIL}", f"/\\{EVIL}", f"https:{EVIL}", f"/%09/{EVIL}",
        f"https://trusted@{EVIL}", f"//{EVIL}%2f%2e%2e", f"\\/\\/{EVIL}",
        f"https://{urlsplit(base).hostname}.{EVIL}", f"/%0d%0a/{EVIL}",
    ]
    for p in payloads:
        try:
            r = requests.get(f"{base}{endpoint}", params={param: p},
                             allow_redirects=False, timeout=TIMEOUT)
        except requests.RequestException:
            continue
        loc = r.headers.get("Location", "")
        if not loc:
            # meta-refresh / JS redirect count too
            if r.status_code == 200 and re.search(
                    rf"(?i)(http-equiv=.refresh[^>]*{re.escape(EVIL)}|location\s*=\s*['\"][^'\"]*{re.escape(EVIL)})",
                    r.text or ""):
                return ProbeResult("open_redirect", True, endpoint, p, r.status_code,
                                   "client-side redirect to an attacker-controlled host",
                                   {"kind": "meta/js", "snippet": (r.text or "")[:200]})
            continue
        host = urlsplit(loc if "//" in loc else f"//{loc.lstrip('/')}").hostname or ""
        if EVIL in (host or "") or EVIL in loc.replace("\\", "/"):
            return ProbeResult("open_redirect", True, endpoint, p, r.status_code,
                               f"redirects off-origin to {loc[:80]}",
                               {"location": loc[:300], "payload": p})
    return ProbeResult("open_redirect", False, endpoint, payloads[0],
                       detail=f"all {len(payloads)} redirect variants constrained to the origin")


@primitive("host_header", group="E", cwe="CWE-644")
def host_header(base: str, endpoint: str, ctx: Ctx | None = None) -> ProbeResult:
    """An attacker Host reflected into an absolute URL — Location, <base href>, or a link."""
    ctx = ctx or Ctx()
    url = f"{base}{endpoint}"
    # The classic sink for this class is a password-reset link, and reset endpoints are POST-only —
    # a GET-only probe reports CLEAR on the very case worth finding.
    email = ctx.opts.get("emails", "probe-9c2f@example.invalid").split(",")[0]
    attempts = [("GET", {}, None)]
    if any(h in endpoint.lower() for h in ("reset", "forgot", "recover", "invite", "verify",
                                           "confirm", "signup", "register")):
        attempts.append(("POST", {"Content-Type": "application/json"}, {"email": email}))
    else:
        attempts.append(("POST", {"Content-Type": "application/json"}, {}))

    spoofs = ({"Host": EVIL},
              {"X-Forwarded-Host": EVIL},
              {"X-Host": EVIL},
              {"X-Forwarded-Server": EVIL},
              {"Host": urlsplit(base).hostname or "", "X-Forwarded-Host": EVIL})

    for method, extra, payload in attempts:
        for headers in spoofs:
            try:
                r = requests.request(method, url, headers={**headers, **extra},
                                     json=payload, allow_redirects=False, timeout=TIMEOUT)
            except requests.RequestException:
                continue
            loc = r.headers.get("Location", "")
            body = r.text or ""
            if EVIL in loc:
                where = "Location header"
            elif re.search(rf"(?i)<base[^>]+href=[\"']https?://{re.escape(EVIL)}", body):
                where = "<base href>"
            elif re.search(rf"(?i)https?://{re.escape(EVIL)}", body):
                where = "response body (a generated link or absolute URL)"
            else:
                continue
            return ProbeResult("host_header", True, endpoint, f"{method} {headers}", r.status_code,
                               f"the request Host is trusted and reflected into the {where}",
                               {"method": method, "headers": headers, "where": where,
                                "location": loc[:200], "snippet": body[:300]})
    return ProbeResult("host_header", False, endpoint,
                       detail="absolute URLs are built from configuration, not the request")


@primitive("csrf", group="D", cwe="CWE-352", needs="an authenticated identity")
def csrf(base: str, endpoint: str, ctx: Ctx | None = None) -> ProbeResult:
    """Read the cookie's SameSite FIRST, then replay tokenless and cross-origin.

    Skipping the cookie check is why most CSRF reports are invalid: SameSite=Lax already blocks the
    cross-site POST, so "no token" alone is not a vulnerability.
    """
    ctx = ctx or Ctx()
    ident = "owner" if "owner" in ctx.identities else next(iter(ctx.identities), "")
    if not ident:
        return blocked("csrf", endpoint, "needs an authenticated identity to replay as")

    # 1) what does the browser actually do with this cookie?
    samesite, set_cookie = "", ""
    try:
        probe = send("GET", f"{base}/", ctx, ident)
        set_cookie = probe.headers.get("Set-Cookie", "")
        m = re.search(r"(?i)samesite=(\w+)", set_cookie)
        samesite = (m.group(1).lower() if m else "")
    except requests.RequestException:
        pass
    cred = ctx.identities.get(ident, "")
    if "samesite=strict" in set_cookie.lower():
        return ProbeResult("csrf", False, endpoint, detail=(
            "session cookie is SameSite=Strict — a cross-site request will not carry it; "
            "chain a same-site XSS or an open redirect instead"),
            evidence={"set_cookie": set_cookie[:200]})

    marker = ctx.fresh_marker("csrf")    # unique per run, or a re-sweep sees its own earlier write
    field = ctx.opts.get("field", "display_name")
    url = f"{base}{endpoint}"
    try:
        before = send("GET", url, ctx, ident)
    except requests.RequestException as e:
        return ProbeResult("csrf", False, endpoint, detail=str(e))

    for ctype, kw in (("application/x-www-form-urlencoded", {"data": {field: marker}}),
                      ("text/plain", {"data": f'{{"{field}":"{marker}"}}'}),
                      ("application/json", {"json": {field: marker}})):
        try:
            w = requests.post(url, headers={"Cookie": cred, "Content-Type": ctype,
                                            "Origin": f"https://{EVIL}",
                                            "Referer": f"https://{EVIL}/"},
                              timeout=TIMEOUT, **kw)
        except requests.RequestException:
            continue
        if w.status_code >= 400:
            continue
        try:
            after = send("GET", url, ctx, ident)
        except requests.RequestException:
            continue
        if marker in (after.text or "") and marker not in (before.text or ""):
            note = ("cookie is SameSite=None — the browser will send it cross-site"
                    if samesite == "none" else
                    "no SameSite attribute — browser default is Lax, so this is exploitable via a "
                    "top-level navigation or a non-browser client" if not samesite else
                    f"cookie SameSite={samesite}")
            return ProbeResult("csrf", True, endpoint, f"{ctype}, no token, Origin: {EVIL}",
                               w.status_code,
                               f"state change accepted with no CSRF token from a foreign origin; "
                               f"{note}",
                               {"content_type": ctype, "samesite": samesite or "(unset)",
                                "set_cookie": set_cookie[:200], "marker": marker,
                                "note": "written to the tester's own object only"})
    return ProbeResult("csrf", False, endpoint,
                       detail="tokenless cross-origin state change rejected",
                       evidence={"set_cookie": set_cookie[:200], "samesite": samesite})


@primitive("clickjacking_header", group="D", cwe="CWE-1021")
def clickjacking_header(base: str, endpoint: str, ctx: Ctx | None = None) -> ProbeResult:
    """Framing controls on the SENSITIVE path. A header check only — rendering proof needs a browser."""
    ctx = ctx or Ctx()
    ident = "owner" if "owner" in ctx.identities else ""
    try:
        r = send("GET", f"{base}{endpoint}", ctx, ident)
    except requests.RequestException as e:
        return ProbeResult("clickjacking_header", False, endpoint, detail=str(e))
    xfo = r.headers.get("X-Frame-Options", "")
    csp = r.headers.get("Content-Security-Policy", "")
    has_fa = "frame-ancestors" in csp.lower()
    if not xfo and not has_fa:
        return ProbeResult("clickjacking_header", True, endpoint, "(no framing control)",
                           r.status_code,
                           "neither X-Frame-Options nor CSP frame-ancestors — the page can be "
                           "framed cross-origin. Confirm with a rendered screenshot before "
                           "reporting; a header alone is a hardening note",
                           {"needs_browser": True, "x_frame_options": xfo, "csp": csp[:200]})
    if xfo.lower().startswith("allow-from") and not has_fa:
        return ProbeResult("clickjacking_header", True, endpoint, xfo, r.status_code,
                           "X-Frame-Options: ALLOW-FROM is unsupported by every modern browser, "
                           "and no frame-ancestors backs it up — effectively unprotected",
                           {"needs_browser": True, "x_frame_options": xfo})
    return ProbeResult("clickjacking_header", False, endpoint,
                       detail=f"framing constrained (XFO={xfo!r}, frame-ancestors={has_fa})")


@primitive("cors_variants", group="D", cwe="CWE-942")
def cors_variants(base: str, endpoint: str, ctx: Ctx | None = None) -> ProbeResult:
    """Reflection, null, prefix/suffix match, scheme downgrade, and a missing Vary: Origin."""
    ctx = ctx or Ctx()
    host = urlsplit(base).hostname or "target"
    origins = [
        (f"https://{EVIL}", "arbitrary origin reflected"),
        ("null", "null origin accepted (reachable from a sandboxed iframe or a data: URL)"),
        (f"https://{host}.{EVIL}", "suffix match — attacker registers target.evil.com"),
        (f"https://{EVIL}/{host}", "path-in-origin confusion"),
        (f"http://{host}", "scheme downgrade to http"),
        (f"https://not{host}", "prefix match"),
    ]
    url = f"{base}{endpoint}"
    for origin, why in origins:
        try:
            r = requests.get(url, headers={"Origin": origin}, timeout=TIMEOUT)
        except requests.RequestException:
            continue
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = (r.headers.get("Access-Control-Allow-Credentials", "") or "").lower() == "true"
        if acao == origin and acac:
            return ProbeResult("cors_variants", True, endpoint, origin, r.status_code,
                               f"ACAO reflects the request origin WITH credentials — {why}",
                               {"origin": origin, "acao": acao, "credentials": True,
                                "vary": r.headers.get("Vary", "")})
        if acao == "*" and acac:
            return ProbeResult("cors_variants", True, endpoint, origin, r.status_code,
                               "ACAO '*' together with allow-credentials (browsers reject this "
                               "pairing, but it signals the policy is not being computed)",
                               {"acao": acao, "note": "verify a browser actually honours it"})
        if acao == origin and not acac and "origin" not in (r.headers.get("Vary", "") or "").lower():
            return ProbeResult("cors_variants", True, endpoint, origin, r.status_code,
                               f"per-origin ACAO with no `Vary: Origin` — a shared cache can serve "
                               f"one origin's ACAO to another ({why})",
                               {"origin": origin, "acao": acao, "vary": r.headers.get("Vary", "")})
    return ProbeResult("cors_variants", False, endpoint,
                       detail=f"all {len(origins)} origin variants rejected")


@primitive("cache_deception", group="E", cwe="CWE-525", detection_only=True,
           needs="an authenticated identity")
def cache_deception(base: str, endpoint: str, ctx: Ctx | None = None) -> ProbeResult:
    """A marker-suffixed static-looking path that returns authenticated content, cacheably.

    Detection only, and on a filename only we will ever request.
    """
    ctx = ctx or Ctx()
    ident = "owner" if "owner" in ctx.identities else next(iter(ctx.identities), "")
    if not ident:
        return blocked("cache_deception", endpoint, "needs an authenticated identity")
    marker = (ctx.marker or "probe-9c2f")
    for suffix in (f"/{marker}.css", f"/{marker}.js", f";{marker}.css", f"%2f{marker}.css",
                   f"/{marker}.jpg"):
        padded = f"{base}{endpoint}{suffix}"
        try:
            authed = send("GET", padded, ctx, ident)
        except requests.RequestException:
            continue
        if authed.status_code >= 400:
            continue
        cc = (authed.headers.get("Cache-Control", "") or "").lower()
        cacheable = "public" in cc or not ("no-store" in cc or "private" in cc or "no-cache" in cc)
        if not cacheable:
            continue
        # the proof: does an UNAUTHENTICATED fetch of the same padded URL return the same content?
        try:
            anon = requests.get(padded, timeout=TIMEOUT)
        except requests.RequestException:
            continue
        if anon.status_code < 400 and shape(anon.text) == shape(authed.text) and len(anon.text or "") > 32:
            return ProbeResult("cache_deception", True, endpoint, suffix, anon.status_code,
                               "authenticated content served, cacheably, under a static-looking "
                               "path and returned to an unauthenticated request",
                               {"padded_path": padded, "cache_control": cc,
                                "detection_only": True,
                                "note": "marker-suffixed filename; no real page path was poisoned"})
        return ProbeResult("cache_deception", True, endpoint, suffix, authed.status_code,
                           "authenticated response is publicly cacheable under a padded static-"
                           "looking path (cache-deception precondition; no shared cache observed "
                           "in front of this host)",
                           {"padded_path": padded, "cache_control": cc, "detection_only": True})
    return ProbeResult("cache_deception", False, endpoint,
                       detail="padded paths 404 or are not cacheable")


@primitive("cache_poison", group="E", cwe="CWE-524", detection_only=True,
           needs="--opt i_understand_cache_impact=1")
def cache_poison(base: str, endpoint: str, ctx: Ctx | None = None) -> ProbeResult:
    """Unkeyed header reflected into a cached response — always on a unique cache-buster.

    Gated behind an explicit flag: a poisoned entry on a real path is served to strangers.
    """
    ctx = ctx or Ctx()
    if str(ctx.opts.get("i_understand_cache_impact", "")).lower() not in ("1", "true", "yes"):
        return blocked("cache_poison", endpoint,
                       "cache probes affect shared infrastructure — pass "
                       "--opt i_understand_cache_impact=1 to run the cache-buster-scoped version")
    marker = f"{ctx.marker or 'probe-9c2f'}.{EVIL}"
    for header in ("X-Forwarded-Host", "X-Forwarded-Scheme", "X-Original-URL", "X-Rewrite-URL",
                   "X-Forwarded-Server", "X-Host"):
        cb = f"cb={random.randrange(10**9, 10**10)}"
        url = f"{base}{endpoint}?{cb}"
        try:
            first = requests.get(url, headers={header: marker}, timeout=TIMEOUT)
            if marker not in (first.text or "") and marker not in str(first.headers):
                continue                                # not reflected; nothing to cache
            time.sleep(0.4)
            second = requests.get(url, timeout=TIMEOUT)   # clean request, same key
        except requests.RequestException:
            continue
        cached = (second.headers.get("X-Cache", "") or "").lower()
        age = second.headers.get("Age", "0")
        if marker in (second.text or ""):
            return ProbeResult("cache_poison", True, endpoint, f"{header}: {marker}",
                               second.status_code,
                               "an unkeyed header was reflected and served back to a clean request "
                               f"on the same cache key (X-Cache={cached!r}, Age={age})",
                               {"header": header, "cache_buster": cb, "x_cache": cached,
                                "age": age, "detection_only": True,
                                "note": "cache-buster-scoped: only this URL was affected"})
    return ProbeResult("cache_poison", False, endpoint,
                       detail="no unkeyed header reflected into a cached response")


@primitive("smuggling_detect", group="E", cwe="CWE-444", detection_only=True,
           needs="--opt allow_timing=1")
def smuggling_detect(base: str, endpoint: str, ctx: Ctx | None = None) -> ProbeResult:
    """Timing-only CL.TE/TE.CL candidate. Never drives a desync — that harms other users.

    A successful desync serves your prefix to the next person through the front-end. This measures
    the back-end blocking on a body that never arrives, and stops there.
    """
    ctx = ctx or Ctx()
    if str(ctx.opts.get("allow_timing", "")).lower() not in ("1", "true", "yes"):
        return blocked("smuggling_detect", endpoint,
                       "timing probe not enabled — pass --opt allow_timing=1")
    url = f"{base}{endpoint}"
    try:
        baseline = median([timed("POST", url, data="x=1")[1] for _ in range(3)])
    except requests.RequestException as e:
        return ProbeResult("smuggling_detect", False, endpoint, detail=str(e))

    # CL.TE: front-end honours Content-Length, back-end honours Transfer-Encoding and waits for
    # a terminating chunk that our body never supplies.
    probes = {
        "CL.TE": ({"Content-Length": "6", "Transfer-Encoding": "chunked"}, "0\r\n\r\nX"),
        "TE.CL": ({"Content-Length": "4", "Transfer-Encoding": "chunked"}, "1\r\nA\r\n0\r\n\r\n"),
        "TE.TE (obfuscated)": ({"Transfer-Encoding": "chunked", "Transfer-encoding": "xchunked"},
                               "0\r\n\r\n"),
    }
    for name, (hdrs, body) in probes.items():
        try:
            times = []
            for _ in range(3):
                try:
                    _, dt = timed("POST", url, headers=hdrs, data=body, timeout=15)
                except requests.Timeout:
                    dt = 15.0
                times.append(dt)
            m = median(times)
        except requests.RequestException:
            continue
        if m >= baseline + 3.0:
            return ProbeResult("smuggling_detect", True, endpoint, name, 0,
                               f"{name} candidate: median {m:.1f}s vs baseline {baseline:.1f}s. "
                               f"Reported as a CANDIDATE — exploitation not attempted, as a "
                               f"successful desync affects other users of the shared front-end",
                               {"variant": name, "baseline_s": round(baseline, 2),
                                "probe_s": round(m, 2), "detection_only": True,
                                "confidence": "timing differential only"})
    return ProbeResult("smuggling_detect", False, endpoint,
                       detail="no timing differential across CL.TE / TE.CL / TE.TE")
