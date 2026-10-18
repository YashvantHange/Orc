#!/usr/bin/env python3
"""
Chain composition: the gate must be able to refuse, or it is decoration.

Severity inflation is the failure mode of chain reporting - three mediums that "could" compose read
like a critical - so every test here is written to make sure the refusal path actually fires. This
session has produced three checks that looked correct while being structurally unable to fail (the
CLEAR fallthrough, the invisible matrix rows, the inert overwrite guard), so the bar is now: prove
the negative case, don't assert it.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "correlate"))
sys.path.insert(0, str(ROOT / "static"))

import chains as CH  # noqa: E402


def link(fid, cls, status=CH.PROVEN, evidence=("T00001",), demonstrated_by="x"):
    return CH.Link(finding_id=fid, vuln_class=cls, status=status,
                   evidence=list(evidence), demonstrated_by=demonstrated_by)


# ===================================================== a link must carry something ===
def test_a_proven_link_with_no_evidence_is_rejected_at_construction():
    with pytest.raises(CH.ChainError, match="nothing behind it"):
        CH.Link(finding_id="F1", vuln_class="ssrf", status=CH.PROVEN, evidence=[])


def test_not_tested_may_carry_no_evidence():
    """Reasoning is allowed to be reasoning - it just carries no severity."""
    l = CH.Link(finding_id="F1", vuln_class="ssrf", status=CH.NOT_TESTED, evidence=[])
    assert l.status == CH.NOT_TESTED


def test_an_unknown_status_is_rejected():
    with pytest.raises(CH.ChainError, match="not one of"):
        CH.Link(finding_id="F1", vuln_class="ssrf", status="probably")


def test_one_finding_is_not_a_chain():
    with pytest.raises(CH.ChainError, match="at least two links"):
        CH.Chain("C1", [link("F1", "ssrf")])


# ============================================ the join is the thing being tested ===
def test_a_fully_demonstrated_chain_passes():
    c = CH.Chain("C1", [link("F1", "open_redirect", demonstrated_by=""),
                        link("F2", "oauth_redirect", demonstrated_by="T00412 -> T00415"),
                        link("F3", "account_takeover", demonstrated_by="T00415 response")])
    ok, reasons = CH.gate(c)
    assert ok, reasons
    assert c.is_complete()
    assert "full chain" in c.severity_basis()


def test_an_undemonstrated_join_refuses_the_chain():
    """Both links are real; the claim that one feeds the other is not. That is the whole risk."""
    c = CH.Chain("C1", [link("F1", "ssrf", demonstrated_by=""),
                        link("F2", "credential_exposure", demonstrated_by="")])
    ok, reasons = CH.gate(c)
    assert not ok
    assert any("never shown" in r for r in reasons)
    assert c.undemonstrated_joins() == ["F1 -> F2"]


def test_severity_comes_from_the_proven_prefix_only():
    """The substitution this module exists to prevent: 2 proven links reported as 4."""
    c = CH.Chain("C1", [
        link("F1", "sourcemap_exposure", demonstrated_by=""),
        link("F2", "admin_endpoint", demonstrated_by="T00101 lists the route F1 leaked"),
        link("F3", "field_authz", status=CH.NOT_TESTED, evidence=[], demonstrated_by=""),
        link("F4", "account_takeover", status=CH.NOT_TESTED, evidence=[], demonstrated_by=""),
    ])
    assert not c.is_complete()
    assert c.broken_at() == 2
    basis = c.severity_basis()
    assert "proven prefix only" in basis
    assert "2 of 4" in basis


def test_a_chain_with_no_proven_first_link_has_no_foothold():
    c = CH.Chain("C1", [link("F1", "ssrf", status=CH.CODE_CONFIRMED, demonstrated_by=""),
                        link("F2", "rce", status=CH.CODE_CONFIRMED)])
    ok, reasons = CH.gate(c)
    assert not ok
    assert any("no proven prefix" in r for r in reasons)
    assert "hypothesis, not a finding" in c.severity_basis()


def test_code_confirmed_links_do_not_extend_the_proven_prefix():
    """code-confirmed is honest, and it is not runtime evidence. It stops the prefix."""
    c = CH.Chain("C1", [link("F1", "ssrf", demonstrated_by=""),
                        link("F2", "rce", status=CH.CODE_CONFIRMED, demonstrated_by="argued")])
    assert len(c.proven_prefix()) == 1


# ============================================================== the gate can fail ===
def test_the_gate_refuses_more_than_it_passes_on_bad_input():
    """A gate that passes everything is decoration. Three bad chains, three refusals."""
    bad = [
        CH.Chain("C1", [link("F1", "a", demonstrated_by=""), link("F2", "b", demonstrated_by="")]),
        CH.Chain("C2", [link("F1", "a", status=CH.NOT_TESTED, evidence=[], demonstrated_by=""),
                        link("F2", "b", status=CH.NOT_TESTED, evidence=[], demonstrated_by="")]),
        CH.Chain("C3", [link("F1", "a", demonstrated_by=""),
                        link("F2", "b", status=CH.NOT_TESTED, evidence=[], demonstrated_by="")]),
    ]
    for c in bad:
        ok, reasons = CH.gate(c)
        assert not ok, f"{c.chain_id} passed the gate and should not have"
        assert reasons


def test_refusing_a_chain_does_not_reject_the_links():
    """The findings still ship; only the composition is refused."""
    c = CH.Chain("C1", [link("F1", "ssrf", demonstrated_by=""),
                        link("F2", "rce", demonstrated_by="")])
    ok, _ = CH.gate(c)
    assert not ok
    assert all(l.evidence for l in c.links), "the links themselves remain evidenced and reportable"


# ==================================================================== round trip ===
def test_save_and_load_round_trip(tmp_path):
    c = CH.Chain("C1", [link("F1", "open_redirect", demonstrated_by=""),
                        link("F2", "oauth", demonstrated_by="T1 -> T2")], summary="ATO path")
    p = CH.save(tmp_path / "chains.json", [c])
    back = CH.load(p)
    assert len(back) == 1
    assert back[0].chain_id == "C1"
    assert back[0].links[1].demonstrated_by == "T1 -> T2"
    assert back[0].is_complete()


def test_malformed_chains_file_raises_rather_than_silently_skipping(tmp_path):
    """A chain that silently loses a link is how a two-link reality becomes a four-link critical."""
    p = tmp_path / "chains.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(CH.ChainError):
        CH.load(p)


def test_missing_file_is_empty_not_an_error(tmp_path):
    assert CH.load(tmp_path / "nope.json") == []


# ======================================================================= the agent ===
def test_the_chain_analyzer_agent_is_registered():
    f = ROOT / ".claude" / "agents" / "chain-analyzer.md"
    assert f.exists()
    text = f.read_text(encoding="utf-8")
    assert text.startswith("---") and "name: chain-analyzer" in text
    # the constraint that defines the role must be stated in it
    assert "demonstrated" in text.lower()
    assert "proven prefix" in text.lower()
