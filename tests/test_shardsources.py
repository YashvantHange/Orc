#!/usr/bin/env python3
"""
A shard must be assigned to a hunter that is actually hunting that class.

These parsers read the skills rather than copying them, so the failure mode is not "the table is
wrong" - it is "the table changed and nothing noticed". Two shapes of silence are dangerous:

  * a skill grows a row and the parser drops it, so a surface exists that no member is ever sent to;
  * a skill grows a row and the parser DEFAULTS its owner, so a member is sent to it by an agent
    that does not hunt that class and returns a confident CLEAR.

Both are the "looks covered, cannot fire" defect that tools/audit_coverage.py exists to catch in the
coverage matrix. So every test here proves a refusal, not just a happy path.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import shardsources as SS  # noqa: E402

AGENTS = ROOT / ".claude" / "agents"


def agent_exists(name: str) -> bool:
    return (AGENTS / f"{name}.md").exists()


# =============================================================== depth: the 12 patterns ===
def test_the_catalog_parses_to_exactly_twelve():
    """The heading promises 12. If the table and the heading ever disagree, fail loudly."""
    assert len(SS.indirection_rows()) == 12


def test_every_indirection_pattern_has_a_real_owner():
    for row in SS.indirection_rows():
        assert row["owner"], f"{row['pattern']} has no owner"
        assert agent_exists(row["owner"]), (
            f"{row['pattern']} maps to {row['owner']}, which is not an agent file - the shard would "
            f"be dispatched to nothing")


def test_each_pattern_carries_the_context_a_member_needs():
    """A shard that says only 'Registry / plugin table' is a topic, not an assignment."""
    for row in SS.indirection_rows():
        assert row["looks_like"].strip(), f"{row['pattern']} has no 'looks like'"
        assert row["resolve_by"].strip(), f"{row['pattern']} has no 'resolve by'"
        assert row["hides"].strip(), f"{row['pattern']} has no 'usually hides'"


def test_an_unmapped_pattern_raises_rather_than_defaulting(monkeypatch):
    trimmed = dict(SS.DEPTH_OWNERS)
    trimmed.pop("Registry / plugin table")
    monkeypatch.setattr(SS, "DEPTH_OWNERS", trimmed)
    with pytest.raises(SS.ShardSourceError, match="DEPTH_OWNERS does not"):
        SS.indirection_rows()


def test_a_missing_heading_raises(monkeypatch, tmp_path):
    empty = tmp_path / "SKILL.md"
    empty.write_text("# nothing here\n", encoding="utf-8")
    monkeypatch.setattr(SS, "DEEP_TRACE", empty)
    with pytest.raises(SS.ShardSourceError, match="not found"):
        SS.indirection_rows()


# ===================================================================== stack: 9 sections ===
def test_all_nine_stacks_are_found_and_the_scaffolding_is_not():
    names = SS.stacks()
    assert len(names) == 9, f"expected 9 stack sections, got {len(names)}: {names}"
    for skipped in ("Step 0", "Step 0b", "Closing"):
        assert not any(n.startswith(skipped) for n in names), f"{skipped} parsed as a stack"


def test_every_stack_surface_has_a_real_owner():
    rows = SS.stack_rows()
    assert len(rows) > 40, f"only {len(rows)} surfaces parsed - the table shape probably changed"
    for r in rows:
        assert agent_exists(r["owner"]), (
            f"{r['stack']} / {r['surface']} maps to {r['owner']}, which is not an agent file")


def test_every_stack_has_at_least_one_shard():
    by_stack = {}
    for r in SS.stack_rows():
        by_stack.setdefault(r["stack"], 0)
        by_stack[r["stack"]] += 1
    for name in SS.stacks():
        assert by_stack.get(name), f"{name} contributed no shards - its table did not parse"


def test_the_second_column_header_varies_so_position_is_what_is_parsed():
    """Two sections head it 'What to look for', seven head it 'Impact'. A parser keyed on the
    header name would silently drop seven stacks."""
    text = SS.STACK_PLAYBOOKS.read_text(encoding="utf-8")
    assert "| Surface | What to look for | Matrix row |" in text
    assert "| Surface | Impact | Matrix row |" in text
    for r in SS.stack_rows():
        assert r["note"].strip(), f"{r['surface']} lost its second column"


def test_markdown_emphasis_in_a_label_still_resolves():
    """`E · Cache poisoning (**detection only**)` must not miss the lookup on its formatting."""
    assert SS._normalise_label("E · Cache poisoning (**detection only**)") == "E · Cache poisoning"
    assert any(r["label"] == "E · Cache poisoning" for r in SS.stack_rows())


def test_the_compound_label_keeps_both_owners():
    """'A · BFLA + F · Secrets' names two classes; losing the second loses half the finding."""
    compound = [r for r in SS.stack_rows() if r["handoff"]]
    assert compound, "the compound label stopped producing a handoff hint"
    for r in compound:
        assert r["owner"] != r["handoff"]
        assert agent_exists(r["handoff"])


def test_non_shard_labels_are_dropped_not_assigned():
    labels = {r["label"] for r in SS.stack_rows()}
    assert "(recon)" not in labels
    assert not any("out of scope" in lab for lab in labels), (
        "a surface the skill marks out of scope became a shard - that is an availability test on a "
        "live host")
    for reason in SS.STACK_NON_SHARDS.values():
        assert reason.strip(), "a non-shard must record WHY, like audit_coverage.DELIBERATE"


def test_an_unmapped_stack_label_raises_rather_than_defaulting(monkeypatch):
    trimmed = dict(SS.STACK_OWNERS)
    trimmed.pop(("C", "SSRF"))
    monkeypatch.setattr(SS, "STACK_OWNERS", trimmed)
    with pytest.raises(SS.ShardSourceError, match="STACK_OWNERS does not cover"):
        SS.stack_rows()


def test_filtering_to_one_stack_returns_only_that_stack():
    rows = SS.stack_rows(stack="Spring Boot")
    assert rows and all("Spring Boot" in r["stack"] for r in rows)
    assert any("actuator" in r["surface"] for r in rows), (
        "the Spring surfaces the matrix will never ask for are the reason this role exists")


def test_an_unknown_stack_raises_rather_than_returning_nothing():
    """Silently returning zero shards would look like 'this stack is clean'."""
    with pytest.raises(SS.ShardSourceError, match="no stack surfaces parsed"):
        SS.stack_rows(stack="CobolOnCogs")


# ================================================= the owner maps agree with the matrix ===
def test_stack_owners_do_not_contradict_the_coverage_matrix():
    """SSRF cannot be server-side's in one table and someone else's in the other."""
    matrix = {}
    for _sec, cls, _pb, _kind, owner in SS.matrix_rows():
        matrix.setdefault(cls.lower(), owner)
    checks = {("C", "SSRF"): "server-side", ("C", "Path traversal"): "server-side",
              ("F", "Secrets exposure"): "authn-crypto", ("F", "Vulnerable components"): "injection"}
    for key, expected in checks.items():
        assert SS.STACK_OWNERS[key] == f"{expected}-hunter", (
            f"{key} is {SS.STACK_OWNERS[key]} here but {expected} in the coverage matrix")


def test_matrix_rows_filter_by_kind():
    src, url = SS.matrix_rows("src"), SS.matrix_rows("url")
    assert src and url and src != url
    assert all(r[3] in ("src", "both") for r in src)
    assert all(r[3] in ("url", "both") for r in url)
