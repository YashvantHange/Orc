#!/usr/bin/env python3
"""
Regression tests for correlate/merge.py's input handling, and for static/run_all.py's language
census that `detect_lang` now depends on.

Why this file exists: `merge()` globbed every `*.json` in `scan/` and did `findings += parsed`.
`language-coverage.json` is a DICT, so `+=` appended its five KEYS as bare strings, and the dedup
loop then called `.get()` on a `str` -> `AttributeError`, which `merge`'s
`except (json.JSONDecodeError, OSError)` does not catch. It sorts before `semgrep.json`, and
`hunt.py` runs the merge immediately after every scan, so every scan that wrote a coverage file
would have crashed the correlate step. It was latent only because no scan had run since the
coverage file was introduced.

Run:  .venv/Scripts/python.exe -m pytest tests/test_correlate_merge.py -q
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "static"))
sys.path.insert(0, str(ROOT / "correlate"))

import _common as C  # noqa: E402
import merge  # noqa: E402
import run_all  # noqa: E402

TARGET = "work/_test_merge_inputs"


@pytest.fixture
def scan_dir():
    d = C.scandir(TARGET)
    d.mkdir(parents=True, exist_ok=True)
    yield d
    shutil.rmtree(C.workdir(TARGET), ignore_errors=True)


def _write(d: Path, name: str, obj) -> None:
    (d / name).write_text(json.dumps(obj), encoding="utf-8")


_REAL_FINDING = {"tool": "semgrep", "file": "a.py", "line": 7,
                 "rule_id": "r1", "severity": "high"}


def test_dict_shaped_coverage_file_does_not_break_the_merge(scan_dir):
    """The exact regression: a dict in scan/ that sorts before the real findings."""
    _write(scan_dir, "language-coverage.json",
           {"target": TARGET, "lang": "c", "file_counts": {"c": 2},
            "unsupported_languages": ["c"], "static_coverage": "none"})
    _write(scan_dir, "semgrep.json", [_REAL_FINDING])

    out = merge.merge(TARGET)                      # used to raise AttributeError
    got = json.loads(Path(out).read_text(encoding="utf-8"))
    assert len(got) == 1, "the real finding must survive"
    assert got[0]["tool"] == "semgrep"


def test_coverage_file_contributes_no_phantom_findings(scan_dir):
    """`findings += <dict>` appended the dict's KEYS. None of them may reach findings.json."""
    keys = ["target", "lang", "file_counts", "unsupported_languages", "static_coverage"]
    _write(scan_dir, "language-coverage.json", {k: "x" for k in keys})
    _write(scan_dir, "semgrep.json", [_REAL_FINDING])

    out = merge.merge(TARGET)
    got = json.loads(Path(out).read_text(encoding="utf-8"))
    assert all(isinstance(f, dict) for f in got), "a bare string reached the findings list"
    assert not ({f.get("file") for f in got} & set(keys)), "a coverage key became a finding"


def test_a_json_that_is_not_a_list_is_skipped_by_shape_not_only_by_name(scan_dir):
    """Skipping by filename alone would break on the next non-findings artifact."""
    _write(scan_dir, "aaa-some-future-artifact.json", {"summary": "not findings"})
    _write(scan_dir, "semgrep.json", [_REAL_FINDING])

    out = merge.merge(TARGET)
    assert len(json.loads(Path(out).read_text(encoding="utf-8"))) == 1


def test_a_list_of_non_dicts_is_filtered(scan_dir):
    _write(scan_dir, "zz-weird.json", ["just", "strings", 7])
    _write(scan_dir, "semgrep.json", [_REAL_FINDING])

    out = merge.merge(TARGET)
    got = json.loads(Path(out).read_text(encoding="utf-8"))
    assert len(got) == 1 and got[0]["tool"] == "semgrep"


def test_merge_still_works_with_no_findings_at_all(scan_dir):
    _write(scan_dir, "language-coverage.json", {"static_coverage": "none"})
    out = merge.merge(TARGET)
    assert json.loads(Path(out).read_text(encoding="utf-8")) == []


# ------------------------------------------------------------------ the language census ---
def test_survey_skips_vendored_trees(tmp_path):
    """detect_lang picks the dominant language from survey, so a venv must not get a vote.

    Measured before the fix: work/_selftest/py_app reported 528 python files because an
    instrumented boot had created .dynvenv inside it.
    """
    (tmp_path / "main.c").write_text("int main(void){return 0;}", encoding="utf-8")
    venv = tmp_path / ".dynvenv" / "Lib" / "site-packages"
    venv.mkdir(parents=True)
    for i in range(50):
        (venv / f"mod{i}.py").write_text("x = 1", encoding="utf-8")

    counts = run_all.survey(str(tmp_path))
    assert counts == {"c": 1}, f"vendored files were counted: {counts}"
    assert run_all.detect_lang(str(tmp_path)) == "c"


def test_detect_lang_names_real_languages_instead_of_auto(tmp_path):
    """"auto" is the most EXPANSIVE mode - every pack plus two CodeQL DBs - not the safest."""
    for ext, want in ((".c", "c"), (".cpp", "cpp"), (".php", "php"), (".go", "go"),
                      (".rs", "rust"), (".java", "java")):
        d = tmp_path / want
        d.mkdir()
        (d / f"f{ext}").write_text("// x", encoding="utf-8")
        assert run_all.detect_lang(str(d)) == want


def test_detect_lang_keeps_auto_for_a_genuinely_mixed_py_js_tree(tmp_path):
    for i in range(5):
        (tmp_path / f"m{i}.py").write_text("x = 1", encoding="utf-8")
        (tmp_path / f"m{i}.js").write_text("let x = 1", encoding="utf-8")
    assert run_all.detect_lang(str(tmp_path)) == "auto"


def test_detect_lang_returns_auto_for_an_empty_tree(tmp_path):
    assert run_all.detect_lang(str(tmp_path)) == "auto"


def test_unsupported_language_is_still_reported_as_not_clean(tmp_path):
    """Naming the language must NOT be mistaken for coverage of it."""
    (tmp_path / "x.c").write_text("int x;", encoding="utf-8")
    counts = run_all.survey(str(tmp_path))
    unreadable = [k for k in counts if k not in run_all.SUPPORTED]
    assert unreadable == ["c"], "a C tree must still count as unreadable by the scanners"
