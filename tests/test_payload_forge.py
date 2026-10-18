"""The payload corpus: it builds sets, and it never sends them."""
import ast
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "dynamic"))

import payloads  # noqa: E402


# ---------------------------------------------------------------- the boundary ----
def test_module_cannot_send_anything():
    """Generation only. A network import here would silently bypass dynamic/scope.py."""
    tree = ast.parse((ROOT / "dynamic" / "payloads.py").read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    forbidden = {"socket", "requests", "httpx", "http", "urllib3", "subprocess", "os"}
    assert not (imported & forbidden), f"payloads.py must not import {imported & forbidden}"
    # urllib is allowed, but only for quoting — not for opening a URL.
    src = (ROOT / "dynamic" / "payloads.py").read_text(encoding="utf-8")
    assert "urlopen" not in src and "urllib.request" not in src


# ------------------------------------------------------------------ generation ----
def test_every_class_carries_an_oracle_and_a_control():
    for cls, spec in payloads.CORPUS.items():
        assert spec["oracle"].strip(), f"{cls} has no oracle — a payload without one is not evidence"
        assert spec["control"].strip(), f"{cls} has no negative control"
        assert spec["cwe"].startswith("CWE-"), f"{cls} has no CWE id"
        assert spec["dialects"], f"{cls} has no dialects"


def test_encodings_are_applied_and_filtered():
    got = payloads.generate("sqli", ["generic"], ["raw", "url", "html-entity"])
    encs = {p.encoding for p in got}
    assert encs == {"raw", "url"}, "html-entity is not valid for sqli and must be dropped"
    raw = next(p for p in got if p.payload == "'")
    url = next(p for p in got if p.encoding == "url" and p.id.endswith("001"))
    assert url.payload == "%27" and raw.encoding == "raw"


def test_markers_and_ports_are_substituted():
    p = payloads.generate("ssrf", ["callback"], ["raw"], marker="mark-1", port=9999)[0]
    assert p.payload == "http://127.0.0.1:9999/mark-1"
    assert "{M}" not in p.payload and "{PORT}" not in p.payload


def test_all_encodings_covers_every_valid_encoding_for_the_class():
    allowed = payloads.CLASS_ENCODINGS["xss"]
    got = payloads.generate("xss", encodings=list(allowed))
    assert {p.encoding for p in got} == set(allowed)


def test_unknown_class_and_dialect_raise():
    with pytest.raises(KeyError):
        payloads.generate("not-a-class")
    with pytest.raises(KeyError):
        payloads.generate("sqli", ["not-a-dialect"])


def test_ids_are_unique():
    for cls in payloads.CORPUS:
        got = payloads.generate(cls, encodings=list(payloads.CLASS_ENCODINGS.get(cls, ("raw",))))
        assert len({p.id for p in got}) == len(got), f"{cls} produced duplicate ids"


# ------------------------------------------------------------------------- cli ----
def test_cli_lists_and_generates(tmp_path):
    hunt = [sys.executable, str(ROOT / "hunt.py"), "payload"]
    r = subprocess.run(hunt + ["--list"], capture_output=True, text=True, cwd=ROOT)
    assert r.returncode == 0 and "sqli" in r.stdout and "refused by design" in r.stdout

    out = tmp_path / "plan.json"
    r = subprocess.run(hunt + ["--class", "ssti", "--encodings", "all", "--json",
                               "--out", str(out)], capture_output=True, text=True, cwd=ROOT)
    assert r.returncode == 0 and out.exists()
    assert "{{7*7}}" in out.read_text(encoding="utf-8")

    r = subprocess.run(hunt + ["--class", "nope"], capture_output=True, text=True, cwd=ROOT)
    assert r.returncode == 2, "an unknown class must be a usage error, not a silent empty set"


def test_rendered_output_states_it_was_not_sent():
    got = payloads.generate("path", encodings=["raw"])
    text = payloads._render(got, "path")
    assert "NOT SENT" in text and "scope-gated" in text
    assert "# tuple:" in text and payloads.tuple_line("path", got) in text
