#!/usr/bin/env python3
"""
The wrapper owns the security-critical arguments.

`ext-tooling` says "no --dump, no --os-shell" as prose. Prose is what an agent under time pressure
re-reads loosely, so the wrapper has to enforce it. These tests are the enforcement's proof, and they
run without installing or launching anything.

The bypasses are the point. A refusal that only catches the obvious spelling is not a control:
a denylist loses to flag aliases, to values that smuggle a second argument, and to --config-style
files that reintroduce a banned option from disk.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "dynamic"))
sys.path.insert(0, str(ROOT / "static"))

import exttool as E  # noqa: E402

CTX = {"proxy_port": 8081, "outdir": "/tmp/out", "binary": "/bin/tool", "limits": {"rps": 2}}
SPEC = E.TargetSpec(url="https://app.example.com/api/x", parameter="id")


# ------------------------------------------------------------------ the allowlist holds ---
def test_unknown_option_is_refused_by_name():
    with pytest.raises(E.ToolError, match="unknown option"):
        E.build_argv("sqlmap", SPEC, CTX, {"nonsense": "1"})


def test_destructive_options_are_refused_with_a_reason():
    """--dump exfiltrates real user data, which disclosure-ethics forbids regardless of scope."""
    for bad in ("dump", "--dump", "os-shell", "os_pwn", "file-write", "sql-shell"):
        with pytest.raises(E.ToolError):
            E.build_argv("sqlmap", SPEC, CTX, {bad: "x"})

    with pytest.raises(E.ToolError, match="refused by policy"):
        E.build_argv("sqlmap", SPEC, CTX, {"--dump": "true"})


def test_forbidden_alias_is_refused_not_just_the_long_spelling():
    """A denylist that only knows --dump is defeated by -T. Aliases are named individually."""
    for alias in ("-T", "-D", "-C"):
        with pytest.raises(E.ToolError, match="refused by policy"):
            E.build_argv("sqlmap", SPEC, CTX, {alias: "users"})


def test_a_config_file_option_cannot_reintroduce_banned_flags():
    """sqlmap --configfile reads options from disk, which would launder every refusal above."""
    with pytest.raises(E.ToolError, match="refused by policy"):
        E.build_argv("sqlmap", SPEC, CTX, {"configfile": "/tmp/evil.ini"})


# ------------------------------------------------- values cannot smuggle a second argument ---
def test_option_values_are_pattern_checked():
    """The subtle bypass: a legal option whose VALUE carries another flag."""
    with pytest.raises(E.ToolError, match="not allowed for this option"):
        E.build_argv("sqlmap", SPEC, CTX, {"technique": "B --dump"})
    with pytest.raises(E.ToolError, match="not allowed for this option"):
        E.build_argv("nuclei", SPEC, CTX, {"severity": "high -headless"})

    ok = E.build_argv("sqlmap", SPEC, CTX, {"technique": "B"})
    assert "--technique=B" in ok


def test_a_legal_value_still_renders_as_one_argv_entry():
    """Even if a value passed the pattern, it must never split into two arguments."""
    argv = E.build_argv("ffuf", SPEC, CTX, {"match_codes": "200,301"})
    assert argv.count("-mc") == 1
    assert "200,301" in argv
    assert not any(" " in a and a.startswith("-") for a in argv)


# --------------------------------------------------------- the forced arguments are forced ---
def test_the_proxy_is_always_present():
    """If the proxy flag can go missing, the traffic leaves the transcript and the scope guard."""
    for tool in E.POLICIES:
        argv = E.build_argv(tool, SPEC, {**CTX, "binary": "/bin/" + tool})
        joined = " ".join(argv)
        assert "127.0.0.1:8081" in joined, tool + " does not route through the gate"


def test_a_caller_cannot_override_a_forced_argument():
    """The proxy and batch flags are not in any allowlist, so they cannot be re-specified."""
    for key in ("proxy", "--proxy", "batch", "output-dir"):
        with pytest.raises(E.ToolError):
            E.build_argv("sqlmap", SPEC, CTX, {key: "http://127.0.0.1:9999"})


def test_rate_is_derived_from_the_scope_not_the_caller():
    slow = E.build_argv("ffuf", SPEC, {**CTX, "limits": {"rps": 2}})
    fast = E.build_argv("ffuf", SPEC, {**CTX, "limits": {"rps": 40}})
    assert slow[slow.index("-rate") + 1] == "2"
    assert fast[fast.index("-rate") + 1] == "40"
    with pytest.raises(E.ToolError):
        E.build_argv("ffuf", SPEC, CTX, {"rate": "1000"})


def test_sqlmap_is_never_handed_interactive_mode():
    argv = E.build_argv("sqlmap", SPEC, CTX)
    assert "--batch" in argv and "--risk=1" in argv and "--level=2" in argv


# ---------------------------------------------------------------------- explain and state ---
def test_explain_matches_what_is_enforced():
    """A drift between the printed policy and the real one sends an agent hunting for workarounds."""
    text = E.explain("sqlmap")
    assert "--dump" in text and "--os-shell" in text
    for name in sorted(E.POLICIES["sqlmap"].opts):
        assert name in text
    assert "--batch" in text


def test_unknown_tool_names_the_known_ones():
    with pytest.raises(E.ToolError, match="unknown tool"):
        E.build_argv("metasploit", SPEC, CTX)


def test_missing_binary_is_blocked_never_clear(tmp_path, monkeypatch):
    """A tool that is not installed must fail loudly - a silent no-op could be read as CLEAR."""
    monkeypatch.setattr(E, "resolve_command", lambda n: None)
    with pytest.raises(E.ToolError, match="not installed"):
        E.run("sqlmap", SPEC, scope_file=str(tmp_path / "s.yml"), slug="t", workdir=tmp_path)


def test_out_of_scope_target_spawns_nothing(tmp_path, monkeypatch):
    """Pre-flight: an unauthorized target must cost zero processes, not a killed one."""
    import scope as S

    scope_file = tmp_path / "scope.yml"
    scope_file.write_text(
        "schema: 1\n"
        "program: {name: t, authorized_by: t}\n"
        "in_scope: {schemes: [https], hosts: [app.example.com]}\n", encoding="utf-8")

    spawned = []
    monkeypatch.setattr(E.subprocess, "Popen",
                        lambda *a, **k: spawned.append(a) or pytest.fail("spawned a process"))
    monkeypatch.setattr(E, "resolve_command", lambda n: ["/bin/" + n])

    with pytest.raises(S.ScopeViolation):
        E.run("sqlmap", E.TargetSpec(url="https://not-authorized.example/x"),
              scope_file=str(scope_file), slug="t", workdir=tmp_path)
    assert not spawned


def test_raw_request_file_round_trips():
    spec = E.TargetSpec(url="https://app.example.com/api/x?id=1", method="POST",
                        headers={"Content-Type": "application/json"}, body='{"a":1}')
    import tempfile
    p = Path(tempfile.mkdtemp()) / "request.txt"
    spec.as_raw_request(p)
    text = p.read_text(encoding="utf-8")
    assert text.startswith("POST /api/x?id=1 HTTP/1.1")
    assert "Host: app.example.com" in text
    assert '{"a":1}' in text
