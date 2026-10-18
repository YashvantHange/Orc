#!/usr/bin/env python3
"""
web_app - a deliberately vulnerable Flask fixture for the live-website pipeline.

**DO NOT FIX THE BUGS IN THIS FILE.** They are seeded on purpose and tests/test_web_acceptance.py
asserts the sweep still finds them. Nothing here is imported by the pipeline; it is a target.

It binds to 127.0.0.1 only, on $PORT, and every route is reachable without the internet. Routes are
NAMED to match `web/sweep.py`'s TARGETING hints - a seeded bug on a path no primitive ever aims at
proves nothing, which is the lesson of the 52-of-54 targeting failure recorded in memory.

Two identities exist so the authorization differential has something to compare: alice/alice-pw and
bob/bob-pw. `/api/safe/*` routes are correctly defended and a HIT on any of them is a false positive.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import sqlite3
import xml.sax

from flask import Flask, Response, jsonify, make_response, redirect, request, session
from jinja2 import Template

app = Flask(__name__)
app.secret_key = "fixture-only-not-a-real-secret"

USERS = {"alice": {"pw": "alice-pw", "id": 1, "role": "user", "email": "alice@fixture.test"},
         "bob": {"pw": "bob-pw", "id": 2, "role": "user", "email": "bob@fixture.test"}}
# The owner marker is the string test_web_acceptance passes as `owner_marker`. The authorization
# differential confirms an IDOR by seeing the OWNER's marker in the OTHER identity's response, so it
# has to actually be in the owner's record.
NOTES = {1: {"id": 1, "owner": "alice", "text": "alice-private marker-A-9c2f"},
         2: {"id": 2, "owner": "bob", "text": "bob-private marker-B-7a10"}}
# Mutated by the prototype-pollution merge below; rendered back so the effect is observable.
DEFAULTS = {"theme": "light", "greeting": "hello"}


def _db() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE items (id INTEGER, name TEXT, secret TEXT)")
    con.executemany("INSERT INTO items VALUES (?,?,?)",
                    # "a" is the seed `sqli_boolean` injects around by default. Without a row the
                    # seed actually matches, the untampered control returns nothing and there is no
                    # difference for the TRUE/FALSE pair to show.
                    [(1, "widget", "s1"), (2, "gadget", "s2"), (3, "doohickey", "s3"),
                     (4, "a", "s4")])
    return con


def _who() -> str | None:
    return session.get("user")


# ============================================================================ identity ===
SIDS: dict = {}


@app.post("/api/login")
def login():
    """SEED session_fixation - the server-side session id is NOT rotated on authentication.

    A pre-auth visitor is given a `sid`; logging in binds the user to that same `sid` instead of
    issuing a new one, so an attacker who fixes a victim's sid before login inherits the session.
    (Flask's own signed cookie cannot demonstrate this: its value IS the serialised data, so it
    changes whenever the data does. The class needs a real server-side id.)
    """
    body = request.get_json(silent=True) or {}
    u, p = body.get("username"), body.get("password")
    if u in USERS and USERS[u]["pw"] == p:
        session["user"] = u
        sid = request.cookies.get("sid")
        if sid:
            SIDS[sid] = u                        # same id, now privileged: fixation
        r = make_response(jsonify(ok=True, user=u))
        if sid:
            r.set_cookie("sid", sid, httponly=False)
        return r
    return jsonify(ok=False), 401


@app.get("/api/me")
def me():
    """Resolves the caller from the server-side `sid`, which is what makes the fixation real.

    An attacker-chosen sid that survives login is only a finding if it is actually authenticated
    afterwards - this is the endpoint that demonstrates it.
    """
    sid = request.cookies.get("sid", "")
    who = SIDS.get(sid) or session.get("user")
    if not who:
        return jsonify(error="auth required"), 401
    return jsonify(user=who, username=who, email=USERS.get(who, {}).get("email", ""),
                   authenticated_via="sid" if SIDS.get(sid) else "session")


@app.post("/api/safe/session/login")
def safe_session_login():
    """NEGATIVE CONTROL - a brand-new id is issued on the privilege change."""
    import secrets
    body = request.get_json(silent=True) or {}
    u, p = body.get("username"), body.get("password")
    if u in USERS and USERS[u]["pw"] == p:
        new = secrets.token_hex(16)
        SIDS[new] = u
        r = make_response(jsonify(ok=True))
        r.set_cookie("sid", new, httponly=True, samesite="Lax")
        return r
    return jsonify(ok=False), 401


@app.post("/api/safe/login")
def safe_login():
    """NEGATIVE CONTROL - rotates the session on authentication."""
    body = request.get_json(silent=True) or {}
    u, p = body.get("username"), body.get("password")
    if u in USERS and USERS[u]["pw"] == p:
        session.clear()
        session["user"] = u
        return jsonify(ok=True)
    return jsonify(ok=False), 401


# =========================================================================== injection ===
@app.get("/api/search")
def search():
    """SEED sqli_error + sqli_boolean - q is concatenated into SQL, errors are returned verbatim."""
    q = request.args.get("q", "")
    con = _db()
    try:
        # `= '{q}'` rather than `LIKE '%{q}%'` on purpose: the boolean oracle sends
        # `a' AND '1'='1` / `a' AND '1'='2` and requires TRUE to match the untampered response
        # while FALSE differs. With the input wrapped in %...% the payload orphans the trailing
        # `%'` and TRUE stops matching the control, so the differential can never confirm.
        rows = con.execute(f"SELECT id, name FROM items WHERE name = '{q}'").fetchall()
    except sqlite3.Error as e:
        # The full exception repr, the way a debug handler leaks it. The oracle matches driver
        # signatures, and the bare message ("unrecognized token") carries none.
        return jsonify(error=f"{type(e).__module__}.{type(e).__name__}: {e}"), 500
    return jsonify(rows=rows, count=len(rows))


@app.get("/api/safe/search")
def safe_search():
    """NEGATIVE CONTROL - parameterised, and the error text never reaches the client."""
    q = request.args.get("q", "")
    try:
        rows = _db().execute("SELECT id, name FROM items WHERE name LIKE ?",
                             (f"%{q}%",)).fetchall()
    except sqlite3.Error:
        return jsonify(error="query failed"), 500
    return jsonify(rows=rows, count=len(rows))


@app.get("/api/preview")
def preview():
    """SEED ssti - tpl is rendered as a Jinja template."""
    tpl = request.args.get("tpl", "hello")
    return Template(tpl).render(user=_who() or "anon")


@app.route("/api/users/lookup", methods=["GET", "POST"])
def lookup():
    """SEED nosqli - an operator object where a scalar was expected is honoured as a filter.

    Accepts the operator three ways because that is how it is probed: a POST JSON body, a JSON
    string in the query, and bracket syntax (`username[$ne]=`) for parsers that build nested
    objects out of the query string.
    """
    body = request.get_json(silent=True) or {}
    bracket = {k: v for k, v in request.args.items() if k.startswith("username[")}
    if bracket:
        op = next(iter(bracket)).split("[", 1)[1].rstrip("]")
        parsed = {op: next(iter(bracket.values()))}
    elif isinstance(body.get("username"), (dict, str)):
        parsed = body["username"]
    else:
        raw = request.args.get("username", "")
        try:
            parsed = json.loads(raw)
        except (TypeError, ValueError):
            parsed = raw
    if isinstance(parsed, dict):                 # {"$ne": ""} matches every user
        op, val = next(iter(parsed.items()), ("", ""))
        if op == "$ne":
            return jsonify(users=[{"username": u, "email": d["email"]}
                                  for u, d in USERS.items() if u != val])
        if op in ("$gt", "$exists", "$where"):
            return jsonify(users=[{"username": u, "email": d["email"], "role": d["role"]}
                                  for u, d in USERS.items()])
        if op == "$regex":
            import re
            return jsonify(users=[{"username": u, "email": d["email"]}
                                  for u in USERS for d in [USERS[u]] if re.search(str(val), u)])
    d = USERS.get(parsed if isinstance(parsed, str) else "")
    return jsonify(users=[{"username": parsed, "email": d["email"]}] if d else [])


@app.post("/api/import")
def xml_import():
    """SEED xxe - external general entities are enabled on the SAX parser."""
    data = request.get_data(as_text=True) or ""
    found = []

    class H(xml.sax.ContentHandler):
        def characters(self, content):
            if content.strip():
                found.append(content)

    parser = xml.sax.make_parser()
    parser.setFeature(xml.sax.handler.feature_external_ges, True)      # the bug
    parser.setContentHandler(H())
    try:
        parser.parse(io.BytesIO(data.encode("utf-8")))
    except Exception as e:                                             # noqa: BLE001
        return jsonify(error=str(e)), 400
    return jsonify(parsed="".join(found))


@app.post("/api/safe/import")
def safe_xml_import():
    """NEGATIVE CONTROL - entity resolution left off, and a DTD is rejected outright."""
    data = request.get_data(as_text=True) or ""
    if "<!DOCTYPE" in data or "<!ENTITY" in data:
        return jsonify(error="DTDs are not accepted"), 400
    return jsonify(parsed="ok")


# ================================================================= objects and merging ===
def _merge(dst: dict, src: dict) -> dict:
    """SEED proto_pollution_server - recursive merge with no key filtering.

    `__proto__` / `constructor` are treated as ordinary keys, so a request can write into DEFAULTS
    and the change is then rendered back to every caller.
    """
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            _merge(dst[k], v)
        else:
            dst[k] = v
    return dst


@app.post("/api/settings")
def settings():
    body = request.get_json(silent=True) or {}
    polluted = _merge(DEFAULTS, body)
    return jsonify(settings=polluted)


@app.post("/api/safe/settings")
def safe_settings():
    """NEGATIVE CONTROL - allow-list of settable keys, and dangerous keys are rejected."""
    body = request.get_json(silent=True) or {}
    if any(k in ("__proto__", "constructor", "prototype") for k in body):
        return jsonify(error="forbidden key"), 400
    return jsonify(settings={k: body[k] for k in body if k in ("theme", "greeting")})


@app.route("/api/profile", methods=["GET", "POST", "PATCH"])
def profile():
    """SEED mass_assignment - the whole body is merged onto the user, role included.

    Also SEED csrf: a state-changing POST with no token and a cookie-only session.
    """
    who = _who()
    if not who:
        return jsonify(error="auth required"), 401
    if request.method in ("POST", "PATCH"):
        body = request.get_json(silent=True) or {}
        USERS[who].update(body)                  # is_admin / role arrive straight from the body
        return jsonify(ok=True, user=USERS[who])
    return jsonify(user={k: v for k, v in USERS[who].items() if k != "pw"})


@app.post("/api/safe/profile")
def safe_profile():
    """NEGATIVE CONTROL - field allow-list plus an origin check."""
    who = _who()
    if not who:
        return jsonify(error="auth required"), 401
    origin = request.headers.get("Origin", "")
    if origin and not origin.startswith(f"http://127.0.0.1:{os.environ.get('PORT', '8031')}"):
        return jsonify(error="bad origin"), 403
    body = request.get_json(silent=True) or {}
    for k in ("email",):
        if k in body:
            USERS[who][k] = body[k]
    return jsonify(ok=True)


# ============================================================== authorization surfaces ===
@app.route("/api/notes/<int:nid>", methods=["GET", "DELETE"])
def note(nid: int):
    """SEED idor_enum - any authenticated user reads any note.

    Also SEED method_override: X-HTTP-Method-Override turns a GET into a DELETE.
    """
    if not _who():
        return jsonify(error="auth required"), 401
    override = request.headers.get("X-HTTP-Method-Override", "").upper()
    method = override or request.method
    rec = NOTES.get(nid)
    if rec is None:
        return jsonify(error="not found"), 404
    if method == "DELETE":
        NOTES.pop(nid, None)                     # no owner check, and reachable via a GET
        return jsonify(deleted=nid, note=rec)
    # Deliberately richer than the not-found body below: the differential discards anything that
    # matches the soft-404 baseline, and two terse JSON objects can collide on shape.
    return jsonify(note=rec, owner=rec["owner"], shared_with=[], tags=["private", "fixture"],
                   created="2026-01-01T00:00:00Z", revision=3,
                   permissions={"read": [rec["owner"]], "write": [rec["owner"]]})


@app.get("/api/safe/notes/<int:nid>")
def safe_note(nid: int):
    """NEGATIVE CONTROL - ownership is enforced and the override header is ignored."""
    who = _who()
    if not who:
        return jsonify(error="auth required"), 401
    rec = NOTES.get(nid)
    if rec is None or rec["owner"] != who:
        return jsonify(error="not found"), 404
    return jsonify(note=rec)


@app.get("/api/admin/users")
def admin_users():
    """SEED bfla_matrix - an admin-only function with no role check at all."""
    if not _who():
        return jsonify(error="auth required"), 401
    return jsonify(users=[{"username": u, **{k: v for k, v in d.items() if k != "pw"}}
                          for u, d in USERS.items()])


@app.get("/api/safe/admin/users")
def safe_admin_users():
    """NEGATIVE CONTROL - the role is actually checked."""
    who = _who()
    if not who:
        return jsonify(error="auth required"), 401
    if USERS.get(who, {}).get("role") != "admin":
        return jsonify(error="forbidden"), 403
    return jsonify(users=list(USERS))


# ====================================================== redirects, headers and caching ===
@app.get("/api/go")
def go():
    """SEED open_redirect - `next` is followed without any host check."""
    return redirect(request.args.get("next", "/"), code=302)


@app.get("/api/safe/go")
def safe_go():
    """NEGATIVE CONTROL - relative paths only."""
    nxt = request.args.get("next", "/")
    if not nxt.startswith("/") or nxt.startswith("//"):
        return jsonify(error="off-site redirect refused"), 400
    return redirect(nxt, code=302)


@app.route("/api/reset", methods=["GET", "POST"])
@app.route("/api/password/reset", methods=["GET", "POST"])
def reset():
    """SEED pwreset_token + host_header.

    Three defects in one realistic sink, which is why this is the classic one:
      * the token is md5(email) truncated - predictable AND short on entropy;
      * the link is built from the request Host / X-Forwarded-Host header, so an attacker controls
        where the victim's reset link points;
      * both are reachable by POST {"email": ...}, which is how the class is actually probed.
    """
    body = request.get_json(silent=True) or {}
    who = body.get("email") or request.args.get("user") or request.args.get("email") or ""
    host = request.headers.get("X-Forwarded-Host") or request.headers.get("Host", "")
    token = hashlib.md5(who.encode()).hexdigest()[:12]           # noqa: S324
    link = f"http://{host}/api/reset/confirm?email={who}&token={token}"
    return jsonify(ok=True, reset_link=link, sent_to=who)


@app.get("/api/reset/confirm")
def reset_confirm():
    who = request.args.get("email") or request.args.get("user", "")
    token = request.args.get("token", "")
    if token == hashlib.md5(who.encode()).hexdigest()[:12]:      # noqa: S324
        return jsonify(ok=True, reset_for=who)
    return jsonify(ok=False), 403


@app.post("/api/safe/reset")
def safe_reset():
    """NEGATIVE CONTROL - a random token, and the link is built from configuration not the Host."""
    import secrets
    body = request.get_json(silent=True) or {}
    who = body.get("email", "")
    return jsonify(ok=True, sent_to=who,
                   reset_link=f"http://127.0.0.1:{os.environ.get('PORT', '8031')}"
                              f"/api/reset/confirm?token={secrets.token_urlsafe(32)}")


@app.get("/account")
def account():
    """SEED clickjacking_header (no X-Frame-Options / frame-ancestors) and cache_deception
    (a per-user page marked publicly cacheable)."""
    who = _who() or "anon"
    r = make_response(f"<html><body><h1>Account</h1><p>user={who}</p>"
                      f"<p>email={USERS.get(who, {}).get('email', '')}</p></body></html>")
    r.headers["Content-Type"] = "text/html"
    r.headers["Cache-Control"] = "public, max-age=600"
    return r


@app.get("/account/<path:extra>")
def account_cache_deception(extra: str):
    """The deception half: a static-looking suffix returns the same private page, cacheable."""
    return account()


@app.get("/api/safe/account")
def safe_account():
    r = make_response("<html><body>Account</body></html>")
    r.headers.update({"Content-Type": "text/html", "X-Frame-Options": "DENY",
                      "Cache-Control": "private, no-store",
                      "Content-Security-Policy": "frame-ancestors 'none'"})
    return r


@app.get("/api/links")
def links():
    """SEED host_header - the Host header is reflected into an absolute URL."""
    host = request.headers.get("Host", "")
    return jsonify(reset=f"http://{host}/api/reset", home=f"http://{host}/")


# =============================================================================== upload ===
ALLOWED_SUFFIXES = (".png", ".jpg", ".txt")


STORE: dict = {}
SERVE_TYPES = {".svg": "image/svg+xml", ".html": "text/html", ".htm": "text/html",
               ".png": "image/png", ".jpg": "image/jpeg", ".txt": "text/plain"}


@app.post("/api/upload")
def upload():
    """SEED upload_bypass - the extension allow-list is checked against the LAST suffix only, and
    `.svg` is treated as a harmless image, so `x.php.png` and `x.svg` both pass.

    The file is then actually STORED and SERVED from the app origin, because that is what the
    primitive confirms on: it fetches the upload back and reads the Content-Type it is served with.
    A stored path that 404s is not a finding.
    """
    # Any field name: the probe chooses its own, and a real upload endpoint that only accepted one
    # hard-coded field would reject the attack before the extension guard was ever reached - which
    # looks exactly like a defended endpoint.
    f = next(iter(request.files.values()), None)
    name = request.args.get("filename") or (f.filename if f else "")
    data = f.read() if f else (request.get_data() or b"")
    if not (name.endswith(ALLOWED_SUFFIXES) or name.endswith(".svg")):
        return jsonify(error="rejected"), 400
    STORE[name] = data
    ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return jsonify(stored=f"/uploads/{name}", url=f"/uploads/{name}",
                   content_type=SERVE_TYPES.get(ext, "application/octet-stream"))


@app.get("/uploads/<path:name>")
def serve_upload(name: str):
    """Serves the upload from the APP ORIGIN with a type derived from its extension - so an .svg
    comes back as active content in the same origin, which is the whole impact."""
    if name not in STORE:
        return jsonify(error="not found"), 404
    ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
    r = make_response(STORE[name])
    r.headers["Content-Type"] = SERVE_TYPES.get(ext, "application/octet-stream")
    return r


@app.post("/api/safe/upload")
def safe_upload():
    """NEGATIVE CONTROL - single-extension allow-list, and the name is not echoed back as a path."""
    name = request.args.get("filename", "")
    if name.count(".") != 1 or not name.endswith(ALLOWED_SUFFIXES):
        return jsonify(error="rejected"), 400
    return jsonify(stored="ok")


# ============================================================================== graphql ===
SCHEMA = {"queryType": {"name": "Query"},
          "types": [{"kind": "OBJECT", "name": "Query",
                     "fields": [{"name": "me", "type": {"name": "User"}},
                                {"name": "allUsers", "type": {"name": "User"}}]},
                    {"kind": "OBJECT", "name": "User",
                     "fields": [{"name": "username", "type": {"name": "String"}},
                                {"name": "email", "type": {"name": "String"}},
                                {"name": "passwordHash", "type": {"name": "String"}}]}]}


@app.route("/graphql", methods=["GET", "POST"])
def graphql():
    """SEED graphql_introspection - introspection is enabled in production."""
    body = request.get_json(silent=True) or {}
    query = body.get("query") or request.args.get("query", "")
    if "__schema" in query or "IntrospectionQuery" in query:
        return jsonify(data={"__schema": SCHEMA})
    if "allUsers" in query:
        return jsonify(data={"allUsers": [{"username": u, "email": d["email"]}
                                          for u, d in USERS.items()]})
    return jsonify(data={"me": {"username": _who() or "anon"}})


# ================================================================================= root ===
@app.get("/")
def index():
    import secrets
    r = make_response(_index_html())
    r.mimetype = "text/html"
    if not request.cookies.get("sid"):
        r.set_cookie("sid", secrets.token_hex(16), httponly=False)   # pre-auth id, never rotated
    return r


@app.get("/api/session/new")
def session_new():
    """An explicit pre-auth id, which is where the fixation probe looks first."""
    import secrets
    r = make_response(jsonify(ok=True))
    r.set_cookie("sid", secrets.token_hex(16), httponly=False)
    return r


def _index_html():
    return (
        "<html><body><h1>selftest web_app</h1>"
        "<a href='/api/search?q=widget'>search</a>"
        "<a href='/api/preview?tpl=hello'>preview</a>"
        "<a href='/api/go?next=/'>go</a>"
        "<a href='/account'>account</a>"
        "<a href='/graphql'>graphql</a>"
        "<a href='/api/users/lookup?username=alice'>lookup</a>"
        "<a href='/api/notes/1'>note</a>"
        "<a href='/api/admin/users'>admin</a>"
        "<a href='/api/profile'>profile</a>"
        "<a href='/api/reset?user=alice'>reset</a>"
        "<a href='/api/links'>links</a>"
        "<form action='/api/upload' method='post'><input name='f' type='file'></form>"
        "<form action='/api/settings' method='post'><input name='theme'></form>"
        "<form action='/api/import' method='post'><input name='xml'></form>"
        # SEED postmessage_origin - a handler that never checks event.origin and writes the
        # message straight into the DOM. Without a browser the primitive must report
        # NEEDS-BROWSER rather than silently clearing the whole client-side group.
        "<div id='out'></div>"
        "<script>window.addEventListener('message', function (e) {"
        "  document.getElementById('out').innerHTML = e.data;"   # no origin check, innerHTML sink
        "});"
        # SEED dom_xss - location.hash straight into innerHTML. A client-side class must come back
        # HIT or NEEDS-BROWSER; silently clearing it would hide the whole client-side group.
        "if (location.hash) {"
        "  document.getElementById('out').innerHTML = decodeURIComponent(location.hash.slice(1));"
        "}"
        "document.write(location.search);"
        # SEED proto_pollution_client - a query-string-to-object walker with no key filtering, so
        # ?__proto__.polluted=1 writes onto Object.prototype and every later object inherits it.
        "function setPath(o, path, v) {"
        "  var p = path.split('.'), cur = o;"
        "  for (var i = 0; i < p.length - 1; i++) {"
        "    if (!cur[p[i]]) { cur[p[i]] = {}; }"
        "    cur = cur[p[i]];"
        "  }"
        "  cur[p[p.length - 1]] = v;"
        "}"
        "window.__cfg = window.__cfg || {};"
        "new URLSearchParams(location.search).forEach(function (v, k) {"
        "  setPath(window.__cfg, k, v);"
        "});"
        "window.__ppCheck = function () { return ({}).polluted; };"
        # The client-PP oracle looks for a TWO-ARGUMENT deep merge on window, under one of
        # merge/deepMerge/deepExtend/extend/mergeDeep/applySettings/setPath/set, and calls it as
        # fn({}, JSON.parse('{\"__proto__\":{...}}')). setPath above is a 3-arg path setter, so the
        # call threw and nothing was polluted - the sink existed but not in the shape anything
        # probes for. This is the classic unsafe recursive merge: __proto__ is an own key on a
        # JSON-parsed object, dst.__proto__ is Object.prototype, so recursing into it pollutes
        # every object in the page.
        "window.deepMerge = function (dst, src) {"
        "  if (typeof src === 'string') { try { src = JSON.parse(src); } catch (e) { return dst; } }"
        "  if (!src || typeof src !== 'object') { return dst; }"
        "  for (var k in src) {"
        "    if (src[k] && typeof src[k] === 'object' && dst[k] && typeof dst[k] === 'object') {"
        "      window.deepMerge(dst[k], src[k]);"
        "    } else {"
        "      dst[k] = src[k];"
        "    }"
        "  }"
        "  return dst;"
        "};"
        "window.__cfg = window.deepMerge(window.__cfg, {});"
        "</script>"
        "</body></html>")


@app.get("/robots.txt")
def robots():
    return Response("User-agent: *\nDisallow: /api/admin/\n", mimetype="text/plain")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "8031")),
            debug=False, threaded=True)
