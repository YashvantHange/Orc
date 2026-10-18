#!/usr/bin/env python3
"""
authz_diff.py — Authorization Differential Harness (the n8n-class 0-day engine).

Broken access control / IDOR / privilege escalation are *logic* bugs no signature rule
finds. This proves them behaviorally: provision several identities with different roles,
then replay each protected request AS EVERY OTHER identity and diff the responses. If a
non-owner / lower-privilege / anonymous identity can read or modify another principal's
resource, that's a confirmed access-control bug.

Config (JSON) describes identities + resources; a built-in --selftest config targets the
fixtures. For a real target the agent writes the config from the routes it discovers.

  python dynamic/authz_diff.py --launch work/_selftest/py_app --selftest
  python dynamic/authz_diff.py --url http://127.0.0.1:8011 --config authz.json
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, asdict, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT / "static"))
# scope guard, not bare requests — see dynamic/scope.py
from scope import http as requests  # noqa: E402
from instrument import TargetProcess  # noqa: E402
import _common as C  # noqa: E402

TIMEOUT = 8


@dataclass
class AuthzFinding:
    kind: str                 # idor | privilege-escalation
    resource: str
    owner: str
    accessed_by: str
    status: int
    detail: str
    evidence: dict = field(default_factory=dict)


def _login(base: str, spec: dict) -> dict:
    """Return the auth header dict for an identity spec, or {} for anon.

    Bearer is the default, but plenty of products authenticate with a vendor-specific
    header instead (Files.com uses X-FilesAPI-Key). Such a header is invisible to any
    tooling that assumes Authorization, so an identity may name its own:

        {"name": "userA", "token": "...", "header": "X-FilesAPI-Key", "scheme": ""}

    `scheme` is the prefix before the value; "" means send the token bare.
    """
    if spec.get("anon"):
        return {}
    if spec.get("headers"):                      # fully explicit, used verbatim
        return dict(spec["headers"])
    if spec.get("token"):
        name = spec.get("header", "Authorization")
        scheme = spec.get("scheme", "Bearer" if name == "Authorization" else "")
        value = f"{scheme} {spec['token']}".strip() if scheme else spec["token"]
        return {name: value}
    login = spec.get("login")
    if not login:
        return {}
    try:
        r = requests.post(f"{base}{login['endpoint']}", json=login.get("body", {}),
                          timeout=TIMEOUT)
        tok = r.json().get(login.get("token_field", "token"))
        return {"Authorization": f"Bearer {tok}"} if tok else {}
    except (requests.RequestException, ValueError):
        return {}


def run_diff(base: str, config: dict) -> list[AuthzFinding]:
    # resolve each identity's auth headers
    identities = {}
    for ident in config["identities"]:
        identities[ident["name"]] = _login(base, ident)

    findings: list[AuthzFinding] = []
    for res in config["resources"]:
        owner = res["owner"]
        marker = res.get("marker", "")
        for name, headers in identities.items():
            if name == owner:
                continue  # the owner is allowed
            try:
                r = requests.request(res.get("method", "GET"), f"{base}{res['path']}",
                                     headers=headers, timeout=TIMEOUT)
            except requests.RequestException:
                continue
            leaked = r.status_code < 400 and (not marker or marker in r.text)
            if leaked:
                kind = "idor" if res.get("kind") != "priv-esc" else "privilege-escalation"
                findings.append(AuthzFinding(
                    kind=kind, resource=res["path"], owner=owner, accessed_by=name,
                    status=r.status_code,
                    detail=f"'{name}' accessed {owner}'s resource {res['path']} "
                           f"({r.status_code})",
                    evidence={"snippet": r.text[:200], "auth": bool(headers)}))
    return findings


SELFTEST_CONFIG = {
    "identities": [
        {"name": "alice", "login": {"endpoint": "/login",
                                    "body": {"user": "alice", "password": "pw-alice"}}},
        {"name": "bob", "login": {"endpoint": "/login",
                                  "body": {"user": "bob", "password": "pw-bob"}}},
        {"name": "viewer", "login": {"endpoint": "/login",
                                     "body": {"user": "viewer", "password": "pw-viewer"}}},
        {"name": "anon", "anon": True},
    ],
    "resources": [
        {"path": "/items/1", "owner": "alice", "marker": "alice-private-note"},
        {"path": "/items/2", "owner": "bob", "marker": "bob-private-note"},
    ],
}


def _write(hint: str, findings: list[AuthzFinding]) -> Path:
    d = C.workdir(hint) / "dynamic"
    d.mkdir(parents=True, exist_ok=True)
    out = d / "authz_diff.json"
    out.write_text(json.dumps([asdict(f) for f in findings], indent=2), encoding="utf-8")
    return out


def _report(base: str, hint: str, config: dict) -> int:
    findings = run_diff(base, config)
    out = _write(hint, findings)
    print(f"\nauthz-diff {base} -> {len(findings)} access-control violations  ({out})")
    for f in findings:
        print(f"  [CONFIRM] {f.kind:20} {f.detail}")
    if not findings:
        print("  (no cross-identity access observed — good, or endpoints need auth first)")
    return 0 if findings else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--url")
    ap.add_argument("--launch")
    ap.add_argument("--entry")
    ap.add_argument("--config", help="path to an authz config JSON")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--slug", help="workdir hint (co-locate output under work/<slug>/); "
                                   "defaults to the url/target")
    ap.add_argument("--scope", help="scope.yml authorizing --url (see dynamic/scope.py)")
    args = ap.parse_args()

    if args.scope:
        import scope as S
        try:
            S.activate(S.Scope.load(args.scope), args.slug or args.url or "url-target",
                       primitive="authz_diff")
        except S.ScopeError as e:
            print(f"scope error: {e}", file=sys.stderr)
            return 2

    config = SELFTEST_CONFIG if args.selftest else (
        json.loads(Path(args.config).read_text(encoding="utf-8")) if args.config else None)
    if not config:
        ap.error("pass --selftest or --config <file>")

    if args.launch:
        with TargetProcess(args.launch, entry=args.entry) as t:
            print(f"launched {t.base_url} (kind={t.kind})")
            time.sleep(1.0)
            return _report(t.base_url, args.slug or args.launch, config)
    elif args.url:
        return _report(args.url, args.slug or args.url, config)
    ap.error("pass --launch <target> or --url <running-instance>")


if __name__ == "__main__":
    sys.exit(main())
