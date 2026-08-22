#!/usr/bin/env python3
"""
fingerprint.py — who is answering, and with what posture.

Two jobs, both zero-payload:
  * tech fingerprint — decides which payload dialects the SSTI/SQLi checks should try, and whether a
    WAF is answering instead of the application (which turns a CLEAR into a BLOCKED).
  * header/cookie/CSP posture — findings in their own right, and the precondition for clickjacking,
    cache deception, CSRF and cookie-chain reports.

Read the AUTHENTICATED, sensitive page. The marketing root's headers say nothing about the page that
matters, and reading the root is the most common way this check produces a wrong answer.
"""
from __future__ import annotations

import re

SERVER_HINTS = [
    ("django", re.compile(r"(?i)csrftoken|__admin_media_prefix__|django")),
    ("flask", re.compile(r"(?i)werkzeug|\bflask\b")),
    ("fastapi", re.compile(r"(?i)fastapi|uvicorn")),
    ("rails", re.compile(r"(?i)_rails_session|x-runtime|authenticity_token")),
    ("express", re.compile(r"(?i)express|connect\.sid")),
    ("next.js", re.compile(r"(?i)__next_data__|/_next/static")),
    ("nuxt", re.compile(r"(?i)__nuxt__")),
    ("laravel", re.compile(r"(?i)laravel_session|xsrf-token")),
    ("spring", re.compile(r"(?i)jsessionid|spring")),
    ("asp.net", re.compile(r"(?i)asp\.net|__viewstate|\.aspx")),
    ("php", re.compile(r"(?i)phpsessid|x-powered-by:\s*php")),
    ("wordpress", re.compile(r"(?i)/wp-content/|/wp-includes/|wp-json")),
]
# Template dialects to try for SSTI, keyed by the stack we detected. Sending all of them at every
# target is noisy; sending the right two is usually enough.
SSTI_DIALECTS = {
    "django": ["{{7*7}}", "{%debug%}"],
    "flask": ["{{7*7}}", "{{7*'7'}}"],
    "fastapi": ["{{7*7}}", "${7*7}"],
    "rails": ["<%=7*7%>", "#{7*7}"],
    "express": ["{{7*7}}", "<%=7*7%>", "${7*7}"],
    "laravel": ["{{7*7}}", "@{{7*7}}"],
    "spring": ["${7*7}", "#{7*7}", "*{7*7}"],
    "asp.net": ["<%=7*7%>", "@(7*7)"],
    "php": ["{{7*7}}", "{php}echo 7*7;{/php}"],
}
DEFAULT_DIALECTS = ["{{7*7}}", "${7*7}", "#{7*7}", "<%=7*7%>", "{{7*'7'}}"]

WAF_HINTS = [
    ("cloudflare", re.compile(r"(?i)cloudflare|__cf_bm|cf-ray")),
    ("akamai", re.compile(r"(?i)akamai|akamaighost")),
    ("aws-waf", re.compile(r"(?i)awselb|x-amzn-waf|x-amz-cf-id")),
    ("imperva", re.compile(r"(?i)incap_ses|visid_incap|imperva")),
    ("f5-bigip", re.compile(r"(?i)bigipserver|f5-")),
    ("sucuri", re.compile(r"(?i)sucuri|x-sucuri-id")),
    ("modsecurity", re.compile(r"(?i)mod_security|modsecurity")),
]

SECURITY_HEADERS = ["content-security-policy", "content-security-policy-report-only",
                    "x-frame-options", "strict-transport-security", "x-content-type-options",
                    "referrer-policy", "permissions-policy", "cross-origin-opener-policy",
                    "cross-origin-resource-policy", "cache-control", "vary"]


def fingerprint(headers: dict, body: str = "") -> dict:
    blob = "\n".join(f"{k}: {v}" for k, v in (headers or {}).items()) + "\n" + (body or "")[:20000]
    tech = [name for name, rx in SERVER_HINTS if rx.search(blob)]
    waf = [name for name, rx in WAF_HINTS if rx.search(blob)]
    dialects = []
    for t in tech:
        for d in SSTI_DIALECTS.get(t, []):
            if d not in dialects:
                dialects.append(d)
    return {
        "server": (headers or {}).get("Server", ""),
        "powered_by": (headers or {}).get("X-Powered-By", ""),
        "tech": tech,
        "waf": waf,
        "ssti_dialects": dialects or DEFAULT_DIALECTS,
    }


def parse_cookies(set_cookie_values: list[str]) -> list[dict]:
    """Flags per cookie. `Domain=.parent` is the one people miss: it makes ANY subdomain XSS or
    takeover a full session compromise, and it is invisible unless you read the attribute."""
    out = []
    for raw in set_cookie_values or []:
        parts = [p.strip() for p in raw.split(";")]
        if not parts or "=" not in parts[0]:
            continue
        name, _, value = parts[0].partition("=")
        attrs = {}
        for p in parts[1:]:
            k, _, v = p.partition("=")
            attrs[k.strip().lower()] = v.strip()
        out.append({
            "name": name.strip(),
            "value_len": len(value),
            "httponly": "httponly" in attrs,
            "secure": "secure" in attrs,
            "samesite": attrs.get("samesite", ""),          # "" = browser default (Lax)
            "domain": attrs.get("domain", ""),
            "path": attrs.get("path", "/"),
            "host_prefix": name.strip().startswith("__Host-"),
            "secure_prefix": name.strip().startswith("__Secure-"),
        })
    return out


def analyze_csp(policy: str) -> dict:
    """What the policy fails to stop. A weak CSP is a finding only once you show the injection it
    doesn't contain — this just tells you which injection to try."""
    if not policy:
        return {"present": False, "issues": ["no CSP"], "directives": {}}
    directives: dict[str, list[str]] = {}
    for part in policy.split(";"):
        toks = part.split()
        if toks:
            directives[toks[0].lower()] = [t.lower() for t in toks[1:]]

    script = directives.get("script-src") or directives.get("default-src") or []
    issues = []
    if "'unsafe-inline'" in script and not any(t.startswith(("'nonce-", "'sha")) for t in script):
        issues.append("script-src 'unsafe-inline' with no nonce/hash — inline injection executes")
    if "'unsafe-eval'" in script:
        issues.append("script-src 'unsafe-eval' — enables CSTI and string-eval sinks")
    if "*" in script or any(t.endswith("*") and len(t) < 4 for t in script):
        issues.append("script-src wildcard — any host may serve script")
    if "data:" in script:
        issues.append("script-src data: — a data: URI can carry script")
    if "frame-ancestors" not in directives:
        issues.append("no frame-ancestors — framing controlled only by X-Frame-Options, if present")
    if "object-src" not in directives and "default-src" not in directives:
        issues.append("object-src unset — plugin/embed vectors uncovered")
    if "base-uri" not in directives:
        issues.append("base-uri unset — an injected <base> re-points every relative script")
    if directives.get("script-src") is None and directives.get("default-src") is None:
        issues.append("neither script-src nor default-src — the policy does not constrain script")
    return {"present": True, "issues": issues, "directives": directives}


def analyze_headers(headers: dict, authenticated: bool = False) -> dict:
    h = {k.lower(): v for k, v in (headers or {}).items()}
    issues = []
    csp = analyze_csp(h.get("content-security-policy", ""))
    if not csp["present"] and h.get("content-security-policy-report-only"):
        issues.append("CSP is report-only — it observes, it does not enforce")
    issues.extend(csp["issues"] if csp["present"] else ["no Content-Security-Policy"])

    if "x-frame-options" not in h and "frame-ancestors" not in csp.get("directives", {}):
        issues.append("no framing control (X-Frame-Options or frame-ancestors) — clickjacking candidate")
    if (h.get("x-frame-options") or "").lower().startswith("allow-from"):
        issues.append("X-Frame-Options: ALLOW-FROM is unsupported by modern browsers — no protection")
    if "strict-transport-security" not in h:
        issues.append("no HSTS")
    if (h.get("x-content-type-options") or "").lower() != "nosniff":
        issues.append("no X-Content-Type-Options: nosniff — MIME sniffing enabled")
    if "referrer-policy" not in h:
        issues.append("no Referrer-Policy — URLs (and any token in them) leak to third parties")
    if h.get("access-control-allow-credentials", "").lower() == "true":
        acao = h.get("access-control-allow-origin", "")
        if acao and acao != "null" and "vary" not in h:
            issues.append(f"ACAO {acao!r} with credentials and no Vary: Origin — cache may cross origins")
    if authenticated:
        cc = (h.get("cache-control") or "").lower()
        if "public" in cc or not cc or ("no-store" not in cc and "private" not in cc):
            issues.append("authenticated response is cacheable (no no-store/private) — "
                          "cache-deception precondition, often a finding on its own")
    for k, v in h.items():
        if k in ("server", "x-powered-by", "x-aspnet-version", "x-generator") and re.search(r"\d+\.\d+", v or ""):
            issues.append(f"version disclosure in {k}: {v}")
    return {"present": {k: h.get(k, "") for k in SECURITY_HEADERS if k in h},
            "csp": csp, "issues": issues}
