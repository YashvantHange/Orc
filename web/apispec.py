#!/usr/bin/env python3
"""
apispec.py — discover the target's own API description.

One request each, and when one lands you have the whole surface with parameter types and, crucially,
the DECLARED auth requirement per endpoint. Any endpoint whose declared security you can ignore in
practice is a finding the target handed you.

A GraphQL schema is treated the same way: every query and mutation is an endpoint, its arguments are
parameters. Read-only; introspection is a read.
"""
from __future__ import annotations

import json

SPEC_PATHS = [
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger/v1/swagger.json",
    "/v2/api-docs", "/v3/api-docs", "/api-docs", "/api/openapi.json", "/api/schema",
    "/api/swagger.json", "/docs/openapi.json", "/.well-known/openapi.json",
]
DOC_UI_PATHS = ["/docs", "/redoc", "/swagger-ui.html", "/swagger", "/graphiql", "/altair"]
GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql"]

INTROSPECTION = {"query": """
{__schema{queryType{name} mutationType{name}
 types{name kind fields{name args{name type{name kind ofType{name}}} type{name kind ofType{name}}}}}}
"""}


def _get_json(sess, url: str):
    try:
        r = sess.get(url)
    except Exception:                                     # noqa: BLE001
        return None, None
    if r.status_code != 200:
        return r.status_code, None
    ctype = (r.headers.get("Content-Type") or "").lower()
    body = r.text or ""
    if "json" in ctype or body.lstrip().startswith(("{", "[")):
        try:
            return r.status_code, json.loads(body)
        except json.JSONDecodeError:
            return r.status_code, None
    if "yaml" in ctype or url.endswith((".yaml", ".yml")):
        try:
            import yaml
            return r.status_code, yaml.safe_load(body)
        except Exception:                                 # noqa: BLE001
            return r.status_code, None
    return r.status_code, None


def find_openapi(sess, base: str) -> tuple[str, dict | None]:
    for p in SPEC_PATHS:
        _, doc = _get_json(sess, base.rstrip("/") + p)
        if isinstance(doc, dict) and (doc.get("openapi") or doc.get("swagger") or doc.get("paths")):
            return p, doc
    return "", None


def endpoints_from_openapi(doc: dict) -> list[dict]:
    """Flatten an OpenAPI/Swagger document into the pipeline's endpoint shape.

    `security` is carried through as `auth_declared` — the gap between what the spec says an endpoint
    requires and what it actually enforces is the cheapest authorization finding there is.
    """
    out: list[dict] = []
    global_sec = bool(doc.get("security"))
    base_path = doc.get("basePath", "") or ""
    servers = doc.get("servers") or []
    prefix = ""
    if servers and isinstance(servers[0], dict):
        from urllib.parse import urlsplit
        prefix = urlsplit(servers[0].get("url", "")).path.rstrip("/")

    for path, item in (doc.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        shared = item.get("parameters") or []
        for method, op in item.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete", "head", "options"):
                continue
            if not isinstance(op, dict):
                continue
            params = []
            for p in list(shared) + list(op.get("parameters") or []):
                if isinstance(p, dict) and p.get("name"):
                    params.append({"name": p["name"], "in": p.get("in", "query"),
                                   "required": bool(p.get("required"))})
            body = op.get("requestBody") or {}
            for _ctype, media in ((body.get("content") or {}) if isinstance(body, dict) else {}).items():
                schema = (media or {}).get("schema") or {}
                for prop in (schema.get("properties") or {}):
                    params.append({"name": prop, "in": "body", "required": False})
            sec = op.get("security", None)
            declared = global_sec if sec is None else bool(sec)
            out.append({
                "path": prefix + base_path + path, "method": method.upper(),
                "params": params, "auth_declared": declared,
                "operation_id": op.get("operationId", ""),
                "summary": (op.get("summary") or "")[:120], "source": "openapi"})
    return out


def find_graphql(sess, base: str) -> dict:
    """Locate a GraphQL endpoint and try introspection. Returns {} when there isn't one."""
    for p in GRAPHQL_PATHS:
        url = base.rstrip("/") + p
        try:
            r = sess.post(url, json=INTROSPECTION, headers={"Content-Type": "application/json"})
        except Exception:                                 # noqa: BLE001
            continue
        if r.status_code not in (200, 400):
            continue
        try:
            doc = json.loads(r.text or "{}")
        except json.JSONDecodeError:
            continue
        if "data" in doc and (doc.get("data") or {}).get("__schema"):
            return {"endpoint": p, "introspection": True, "schema": doc["data"]["__schema"]}
        if "errors" in doc:
            # It IS GraphQL — it just refused introspection. Still an endpoint, and the refusal
            # message often names the disabling middleware.
            return {"endpoint": p, "introspection": False,
                    "error": json.dumps(doc["errors"])[:300], "schema": None}
    return {}


def endpoints_from_graphql(gql: dict) -> list[dict]:
    """Every query/mutation is a route; its args are parameters."""
    schema = gql.get("schema")
    if not schema:
        return []
    ep = gql.get("endpoint", "/graphql")
    by_name = {t.get("name"): t for t in (schema.get("types") or []) if isinstance(t, dict)}
    out = []
    for root_key, kind in (("queryType", "query"), ("mutationType", "mutation")):
        root = (schema.get(root_key) or {}).get("name")
        t = by_name.get(root)
        if not t:
            continue
        for f in (t.get("fields") or []):
            out.append({
                "path": ep, "method": "POST", "graphql_operation": kind,
                "graphql_field": f.get("name"),
                "params": [{"name": a.get("name"), "in": "graphql-arg", "required": False}
                           for a in (f.get("args") or [])],
                "auth_declared": None, "source": "graphql"})
    return out


def discover(sess, base: str) -> dict:
    """Everything above, in one pass."""
    result: dict = {"openapi_path": "", "openapi": None, "endpoints": [], "graphql": {},
                    "doc_ui": [], "oidc": None}

    path, doc = find_openapi(sess, base)
    if doc:
        result["openapi_path"], result["openapi"] = path, doc
        result["endpoints"].extend(endpoints_from_openapi(doc))

    gql = find_graphql(sess, base)
    if gql:
        result["graphql"] = {k: v for k, v in gql.items() if k != "schema"}
        result["graphql"]["has_schema"] = bool(gql.get("schema"))
        result["endpoints"].extend(endpoints_from_graphql(gql))
        result["_graphql_schema"] = gql.get("schema")

    for p in DOC_UI_PATHS:
        try:
            r = sess.get(base.rstrip("/") + p)
        except Exception:                                 # noqa: BLE001
            continue
        if r.status_code == 200 and re_has_docs(r.text):
            result["doc_ui"].append(p)

    _, oidc = _get_json(sess, base.rstrip("/") + "/.well-known/openid-configuration")
    if isinstance(oidc, dict) and oidc.get("authorization_endpoint"):
        # the entire SSO surface in one document — every endpoint here is an authn-crypto lead
        result["oidc"] = {k: oidc.get(k) for k in
                          ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri",
                           "userinfo_endpoint", "end_session_endpoint",
                           "grant_types_supported", "response_types_supported",
                           "id_token_signing_alg_values_supported",
                           "code_challenge_methods_supported")}
    return result


def re_has_docs(text: str) -> bool:
    t = (text or "")[:4000].lower()
    return any(k in t for k in ("swagger", "redoc", "openapi", "graphiql", "api documentation"))
