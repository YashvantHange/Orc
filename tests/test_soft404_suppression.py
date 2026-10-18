#!/usr/bin/env python3
"""
The soft-404 guard must not suppress the findings it exists to protect.

`_endpoint_is_real` was added because a sweep against a target that answers 200 for every path
returned 5 HITs of which 3 were on endpoints that do not exist. Its own docstring draws the line:
suppression "is NOT tolerable here, where a false match SUPPRESSES A CONFIRMED FINDING".

It then did exactly that. The check GETs `base + endpoint` verbatim, and a TEMPLATED endpoint is
`/api/notes/{id}` - a URL that 404s on every target in existence. So on any app with a stable 404
shape, every templated primitive (idor_enum, method_override) had its confirmation downgraded to
NOT-CONFIRMED. Found against the seeded fixture: idor_enum confirmed when called directly and came
back NOT-CONFIRMED through the sweep.

Both directions are tested here, because a guard that cannot refuse is decoration and a guard that
refuses everything is worse than none.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "web"))
sys.path.insert(0, str(ROOT / "dynamic"))

import primitives as P  # noqa: E402
import sweep  # noqa: E402


class FakeResp:
    def __init__(self, text=""):
        self.text = text
        self.status_code = 200
        self.headers = {}


def ctx_with_shell(shell_body: str, ids: str = "1,2") -> P.Ctx:
    c = P.Ctx()
    c.baselines = {"soft_404": {"fingerprint": P.shape(shell_body)}}
    c.opts = {"ids": ids}
    return c


def record_gets(monkeypatch, responses: dict):
    """Serve canned bodies by path and record what was actually requested."""
    seen = []

    def fake_get(url, **kw):
        seen.append(url)
        for path, body in responses.items():
            if url.endswith(path):
                return FakeResp(body)
        return FakeResp(responses.get("*", ""))

    monkeypatch.setattr(sweep.probe.requests, "get", fake_get)
    return seen


SHELL = "<html><body>Not Found</body></html>"
REAL = '{"note": {"id": 1, "owner": "alice"}, "tags": ["x"], "revision": 3}'


# ===================================== the false suppression this test was written for ===
def test_a_templated_endpoint_is_substituted_before_the_check(monkeypatch):
    """The bug: GET /api/notes/{id} is a 404 everywhere, so the literal matched the shell."""
    seen = record_gets(monkeypatch, {"/api/notes/1": REAL, "*": SHELL})
    ctx = ctx_with_shell(SHELL, ids="1,2")

    assert sweep._endpoint_is_real("http://t", "/api/notes/{id}", ctx, {}) is True, (
        "a templated endpoint was judged non-existent, which suppresses every confirmation the "
        "templated primitives can produce")
    assert any(u.endswith("/api/notes/1") for u in seen), f"placeholder was not substituted: {seen}"
    assert not any("{id}" in u for u in seen), f"the literal template was requested: {seen}"


def test_the_id_comes_from_the_same_opt_the_primitives_use(monkeypatch):
    seen = record_gets(monkeypatch, {"/api/notes/77": REAL, "*": SHELL})
    ctx = ctx_with_shell(SHELL, ids="77,88")
    assert sweep._endpoint_is_real("http://t", "/api/notes/{id}", ctx, {}) is True
    assert any(u.endswith("/api/notes/77") for u in seen)


def test_any_placeholder_name_is_substituted(monkeypatch):
    seen = record_gets(monkeypatch, {"/api/users/1/posts/1": REAL, "*": SHELL})
    ctx = ctx_with_shell(SHELL)
    assert sweep._endpoint_is_real("http://t", "/api/users/{userId}/posts/{postId}", ctx, {}) is True
    assert not any("{" in u for u in seen)


# ========================================== and the guard must still be able to refuse ===
def test_a_path_that_really_is_the_shell_is_still_suppressed(monkeypatch):
    """The negative case. Without this, the fix above would just disable the guard."""
    record_gets(monkeypatch, {"*": SHELL})
    ctx = ctx_with_shell(SHELL)
    assert sweep._endpoint_is_real("http://t", "/does/not/exist", ctx, {}) is False


def test_a_templated_path_whose_substitution_is_the_shell_is_suppressed(monkeypatch):
    """Substituting must not make every templated path automatically 'real'."""
    record_gets(monkeypatch, {"*": SHELL})
    ctx = ctx_with_shell(SHELL)
    assert sweep._endpoint_is_real("http://t", "/api/ghost/{id}", ctx, {}) is False


def test_a_real_endpoint_is_real(monkeypatch):
    record_gets(monkeypatch, {"/api/search": REAL, "*": SHELL})
    ctx = ctx_with_shell(SHELL)
    assert sweep._endpoint_is_real("http://t", "/api/search", ctx, {}) is True


def test_without_a_baseline_nothing_is_downgraded(monkeypatch):
    record_gets(monkeypatch, {"*": SHELL})
    c = P.Ctx()
    c.opts = {}
    assert sweep._endpoint_is_real("http://t", "/anything", c, {}) is True, (
        "with no baseline the guard cannot judge, so it must not suppress")


def test_the_result_is_cached_per_endpoint(monkeypatch):
    seen = record_gets(monkeypatch, {"/api/notes/1": REAL, "*": SHELL})
    ctx, cache = ctx_with_shell(SHELL), {}
    for _ in range(3):
        sweep._endpoint_is_real("http://t", "/api/notes/{id}", ctx, cache)
    assert len(seen) == 1, f"the existence check was repeated {len(seen)} times"
