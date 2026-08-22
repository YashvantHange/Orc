#!/usr/bin/env python3
"""
Regression tests for the hunt.py orchestration layer and the tools under the skills.

Run:  .venv/Scripts/python.exe -m pytest tests/test_orchestration.py -q
  or: .venv/Scripts/python.exe tests/test_orchestration.py   (no pytest needed)

These guard the invariants the skills depend on: profile.json round-trips + migrates, corrupt
caches fall back to recompute, per-slug state stays isolated, URL-hints don't crash the workdir,
and the CVSS math stays correct.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "static"))
sys.path.insert(0, str(ROOT / "reports"))
sys.path.insert(0, str(ROOT / "dynamic"))

import hunt  # noqa: E402
import _common as C  # noqa: E402
import cvss  # noqa: E402


def test_cvss_anchors():
    assert cvss.score_vector("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")[:2] == (9.8, "Critical")
    assert cvss.score_vector("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N")[:2] == (6.5, "Medium")
    assert cvss.score_vector("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")[:2] == (6.1, "Medium")
    try:
        cvss.score_vector("AV:X/AC:L")
        raise AssertionError("expected ValueError on bad metric")
    except ValueError:
        pass


def test_slug_sanitizes_url_hint():
    # a URL hint must never produce a Windows-illegal path (was a crash: WinError 123)
    s = C.slug("http://127.0.0.1:62664")
    assert ":" not in s and "/" not in s and s


def test_profile_roundtrip_and_migration(tmp_path=None):
    tgt = str(ROOT / "work" / "_selftest" / "py_app")
    hunt.save_profile(tgt, base_url="http://127.0.0.1:9999", kind="python", endpoints=["/a", "/b"])
    prof = hunt.load_profile(tgt)
    assert prof["schema"] == hunt.PROFILE_SCHEMA
    assert prof["base_url"] == "http://127.0.0.1:9999"
    assert prof["endpoints"] == ["/a", "/b"]
    assert "updated_at" in prof
    # migration: an old schema-0 profile without new keys still loads + upgrades on save
    p = hunt.profile_path(tgt)
    p.write_text(json.dumps({"schema": 0, "target": tgt, "slug": "py_app"}), encoding="utf-8")
    hunt.save_profile(tgt, base_url="http://x")
    assert hunt.load_profile(tgt)["schema"] == hunt.PROFILE_SCHEMA


def test_corrupt_profile_falls_back(tmp_path=None):
    tgt = str(ROOT / "work" / "_selftest" / "py_app")
    hunt.profile_path(tgt).write_text("{ not json", encoding="utf-8")
    prof = hunt.load_profile(tgt)  # must not raise; recomputes a minimal profile
    assert prof["slug"] == "py_app" and prof["schema"] == hunt.PROFILE_SCHEMA


def test_per_slug_isolation():
    a = C.workdir("work/_selftest/py_app")
    b = C.workdir("owner/some-other-repo")
    assert a != b and a.name != b.name  # different targets -> different workdirs, no state mixing


def test_slug_generic_leaf_does_not_collide():
    # was a real state-mixing bug: every target's <slug>/src landed in one shared work/src/ bucket,
    # merging scan output, findings.json AND evidence bundles across targets.
    assert C.slug("work/lightrag/src") != C.slug("work/_selftest_web/web/js/src")
    assert C.slug("work/lightrag/src") == "lightrag"
    # a real target directory keeps its own name — only a generic leaf walks up
    assert C.slug("work/_selftest/py_app") == "py_app"
    assert C.slug("work/_selftest/node_app") == "node_app"


def test_normalize_origin_and_web_slug():
    import _common as _C
    assert _C.is_url("https://a.example.com") and not _C.is_url("work/x/src")
    # one host = one workdir, whatever the path
    assert _C.web_slug("https://App.Example.com/api/x") == _C.web_slug("https://app.example.com/other")
    assert _C.normalize_origin("https://app.example.com:443/x?y=1") == "https://app.example.com"
    assert _C.normalize_origin("http://h:8080/x") == "http://h:8080"
    assert _C.target_kind("https://x.example") == "url"
    assert _C.target_kind("work/x/src") == "src"
    assert _C.target_kind("https://x.example", "work/x/src") == "grey"


def test_scope_allows_and_refuses():
    import scope as S
    sc = S.Scope(raw=S._SELFTEST_SCOPE, path=None, _digest="t")
    sc._validate()
    for method, url, want, why in S._SELFTEST_CASES:
        assert sc.explain(method, url)["allowed"] == want, f"{method} {url}: {why}"


def test_scope_refuses_without_file_and_exits_three():
    import scope as S
    assert S.EXIT_SCOPE_REFUSAL == 3
    try:
        hunt._resolve_target(url="https://not-authorized.example/api")
        raise AssertionError("expected a ScopeViolation for a live host with no scope file")
    except S.ScopeViolation:
        pass


def test_scope_token_bucket_throttles():
    import time as _t
    import scope as S
    b = S._TokenBucket(rps=10, burst=1)
    b.acquire()
    t0 = _t.monotonic()
    b.acquire()
    assert _t.monotonic() - t0 >= 0.05


def test_http_facade_is_a_noop_without_a_scope():
    # the entire local-target pipeline depends on this: with no scope active, `from scope import
    # http as requests` must BE requests, or every existing flow changes behaviour.
    import requests as real
    import scope as S
    S.deactivate()
    assert S.http.RequestException is real.RequestException
    assert S.http._target() is real


def test_no_bare_requests_import_outside_scope():
    # the choke point rots the first time someone adds a primitive with `import requests`
    import re as _re
    offenders = []
    for d in ("dynamic", "web"):
        for p in (ROOT / d).rglob("*.py"):
            if p.name == "scope.py":
                continue
            for i, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if _re.match(r"^\s*(?:import requests|from requests import)\b", line):
                    offenders.append(f"{p.relative_to(ROOT)}:{i}")
    assert not offenders, ("these must import `from scope import http as requests` so live-target "
                           f"requests stay scoped and transcribed: {offenders}")


def test_endpoint_path_templating():
    sys.path.insert(0, str(ROOT / "web"))
    import recon
    assert recon.template_path("/items/42")[0] == "/items/{id}"
    assert recon.template_path("/a/550e8400-e29b-41d4-a716-446655440000/b")[0] == "/a/{id}/b"
    assert recon.template_path("/api/users")[0] == "/api/users"     # not everything is an id
    assert recon.template_path("/items/42")[1] == ["42"]


def _run_all() -> int:
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"  PASS {fn.__name__}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"  FAIL {fn.__name__}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run_all())
