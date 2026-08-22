#!/usr/bin/env python3
"""Access-control primitives — IDOR enumeration, BFLA matrix, mass assignment, method override.

Every one of these needs at least two identities. With one account they cannot prove anything, so
they return BLOCKED rather than a verdict — an under-tested authorization class recorded as CLEAR is
the worst output this pipeline can produce.
"""
from __future__ import annotations

from . import Ctx, ProbeResult, TIMEOUT, blocked, primitive, requests, send, shape

PRIVILEGED_VERBS = ("POST", "PUT", "PATCH")
READ_VERBS = ("GET",)


@primitive("idor_enum", group="A", cwe="CWE-639", needs="two identities (owner + other)")
def idor_enum(base: str, endpoint: str, ctx: Ctx | None = None) -> ProbeResult:
    """Walk the owner's object ids as a second identity; confirm on the owner's marker, not a 200.

    `endpoint` is a templated path (`/api/items/{id}`); values come from --opt ids=1,2,3 or recon.
    """
    ctx = ctx or Ctx()
    owner = ctx.identities.get("owner")
    other = ctx.identities.get("other")
    if not owner or not other:
        return blocked("idor_enum", endpoint,
                       "needs two same-privilege identities (owner + other); one account cannot "
                       "prove IDOR")
    marker = ctx.opts.get("owner_marker") or "marker-A-9c2f"
    ids = [i for i in str(ctx.opts.get("ids", "1,2,3")).split(",") if i]

    for i in ids:
        path = endpoint.replace("{id}", i)
        url = f"{base}{path}"
        try:
            as_owner = send("GET", url, ctx, "owner")
            as_other = send("GET", url, ctx, "other")
            as_anon = requests.get(url, timeout=TIMEOUT)
        except requests.RequestException:
            continue
        if as_owner.status_code >= 400 or marker not in (as_owner.text or ""):
            continue                                    # not the owner's object; nothing to prove
        for label, resp in (("other", as_other), ("anon", as_anon)):
            if resp.status_code < 400 and marker in (resp.text or ""):
                if ctx.is_soft_404(resp):
                    continue                            # the SPA shell, not the object
                return ProbeResult("idor_enum", True, path, f"id={i} as {label}", resp.status_code,
                                   f"'{label}' read the owner's object — response carries the "
                                   f"owner-only marker {marker!r}",
                                   {"identity": label, "marker": marker,
                                    "owner_status": as_owner.status_code,
                                    "snippet": (resp.text or "")[:300],
                                    "note": "stopped at the first record; impact argued in prose"})
    return ProbeResult("idor_enum", False, endpoint,
                       detail=f"owner marker not reachable by other/anon across ids {ids}")


@primitive("bfla_matrix", group="A", cwe="CWE-862", needs="two roles (low + high privilege)")
def bfla_matrix(base: str, endpoint: str, ctx: Ctx | None = None) -> ProbeResult:
    """Every privileged verb, as every lower role. Role gaps are the half most audits miss."""
    ctx = ctx or Ctx()
    low = [n for n in ("other", "member", "viewer", "user") if n in ctx.identities]
    if not low:
        return blocked("bfla_matrix", endpoint,
                       "needs a lower-privilege identity to replay privileged verbs as")
    tried, hits = [], []
    for name in low:
        for verb in READ_VERBS + PRIVILEGED_VERBS:
            try:
                r = send(verb, f"{base}{endpoint}", ctx, name,
                         json={} if verb in PRIVILEGED_VERBS else None)
            except requests.RequestException:
                continue
            tried.append(f"{verb} as {name} -> {r.status_code}")
            if r.status_code < 400 and not ctx.is_soft_404(r):
                hits.append({"verb": verb, "identity": name, "status": r.status_code,
                             "snippet": (r.text or "")[:200]})
    if hits:
        h = hits[0]
        return ProbeResult("bfla_matrix", True, endpoint, f"{h['verb']} as {h['identity']}",
                           h["status"],
                           f"{len(hits)} privileged operation(s) succeeded for a lower role",
                           {"hits": hits, "enumerated": tried})
    return ProbeResult("bfla_matrix", False, endpoint,
                       detail=f"all {len(tried)} verb x role combinations rejected",
                       evidence={"enumerated": tried})


@primitive("mass_assignment", group="A", cwe="CWE-915", needs="an authenticated identity")
def mass_assignment(base: str, endpoint: str, ctx: Ctx | None = None) -> ProbeResult:
    """Bind a protected field with a marker, then re-read the object to prove it persisted."""
    ctx = ctx or Ctx()
    ident = "owner" if "owner" in ctx.identities else next(iter(ctx.identities), "")
    if not ident:
        return blocked("mass_assignment", endpoint, "needs an authenticated identity")
    marker = ctx.fresh_marker("ma")      # unique per run, or a re-sweep sees its own earlier write
    protected = [f.strip() for f in str(ctx.opts.get(
        "fields", "role,is_admin,isAdmin,admin,permissions,plan,tier,verified,email_verified,"
                  "balance,credits,owner,user_id,tenant_id")).split(",") if f.strip()]

    url = f"{base}{endpoint}"
    try:
        before = send("GET", url, ctx, ident)
    except requests.RequestException as e:
        return ProbeResult("mass_assignment", False, endpoint, detail=str(e))

    for field in protected:
        for verb in ("PATCH", "PUT", "POST"):
            try:
                w = send(verb, url, ctx, ident, json={field: marker})
            except requests.RequestException:
                continue
            if w.status_code >= 400:
                continue
            try:
                after = send("GET", url, ctx, ident)
            except requests.RequestException:
                continue
            # it must PERSIST — an echo in the write response can just be request reflection
            if marker in (after.text or "") and marker not in (before.text or ""):
                return ProbeResult("mass_assignment", True, endpoint, f"{verb} {field}={marker}",
                                   w.status_code,
                                   f"protected field {field!r} bound from the request body and "
                                   f"persisted (confirmed by re-read)",
                                   {"field": field, "verb": verb, "marker": marker,
                                    "after_snippet": (after.text or "")[:300]})
    return ProbeResult("mass_assignment", False, endpoint,
                       detail=f"none of {len(protected)} protected fields bound",
                       evidence={"enumerated_fields": protected})


@primitive("method_override", group="A", cwe="CWE-650")
def method_override(base: str, endpoint: str, ctx: Ctx | None = None) -> ProbeResult:
    """A verb that 403/405s directly, succeeding through an override header or _method."""
    ctx = ctx or Ctx()
    ident = "owner" if "owner" in ctx.identities else ""
    url = f"{base}{endpoint}"
    # DELETE is deliberately absent: the scope guard denies it, and proving override with a
    # destructive verb against real data is not something we do.
    for target_verb in ("PUT", "PATCH"):
        try:
            direct = send(target_verb, url, ctx, ident, json={})
        except requests.RequestException:
            continue
        if direct.status_code not in (403, 405, 501):
            continue                                  # nothing was blocking it; no bypass to show
        for header in ("X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method"):
            try:
                r = send("POST", url, ctx, ident, json={}, headers={header: target_verb})
            except requests.RequestException:
                continue
            if r.status_code < 400:
                return ProbeResult("method_override", True, endpoint, f"{header}: {target_verb}",
                                   r.status_code,
                                   f"{target_verb} returned {direct.status_code} directly but "
                                   f"succeeded through {header}",
                                   {"direct_status": direct.status_code, "header": header})
        try:
            r = send("POST", url, ctx, ident, data={"_method": target_verb})
        except requests.RequestException:
            continue
        if r.status_code < 400:
            return ProbeResult("method_override", True, endpoint, f"_method={target_verb}",
                               r.status_code,
                               f"{target_verb} blocked directly but reachable via the _method field",
                               {"direct_status": direct.status_code})
    return ProbeResult("method_override", False, endpoint,
                       detail="no verb-override path around the method restriction")


@primitive("rate_limit", group="A", cwe="CWE-307",
           needs="scope rps high enough to reach the lockout threshold")
def rate_limit(base: str, endpoint: str, ctx: Ctx | None = None) -> ProbeResult:
    """Deliberately-wrong credentials for an account you own, watching for 429 / lockout / CAPTCHA.

    Self-refuses when the engagement's own rate limit is slower than any plausible threshold —
    firing five requests at 2 rps proves nothing and must never read as CLEAR.
    """
    ctx = ctx or Ctx()
    import scope as S
    sc = S.active().scope if S.active() else None
    rps = sc.limits["rps"] if sc else 50.0
    attempts = int(ctx.opts.get("attempts", 30))
    if rps < 5:
        return blocked("rate_limit", endpoint,
                       f"scope permits {rps} rps; the lockout threshold cannot be reached without "
                       f"exceeding it. Raise limits.rps only if the program's policy allows it")
    user = ctx.opts.get("username", "probe-user-9c2f")
    seen = []
    for i in range(attempts):
        try:
            r = requests.post(f"{base}{endpoint}",
                              json={"username": user, "password": f"wrong-{i}-9c2f"},
                              timeout=TIMEOUT)
        except requests.RequestException:
            break
        seen.append(r.status_code)
        if r.status_code == 429 or "captcha" in (r.text or "").lower() or "locked" in (r.text or "").lower():
            return ProbeResult("rate_limit", False, endpoint, f"{i + 1} attempts", r.status_code,
                               f"throttled after {i + 1} attempts — anti-automation present",
                               {"statuses": seen})
    return ProbeResult("rate_limit", True, endpoint, f"{len(seen)} attempts",
                       seen[-1] if seen else 0,
                       f"{len(seen)} failed authentication attempts with no 429, lockout or CAPTCHA",
                       {"statuses": seen, "note": "wrong credentials for a probe account only; "
                                                  "no real account was targeted"})
