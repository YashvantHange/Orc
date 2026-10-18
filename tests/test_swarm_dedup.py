#!/usr/bin/env python3
"""
Thirty members reaching one bug must produce one report candidate, not thirty.

A duplicate submission is a wasted one on the programs this pipeline targets, and at width 30 the
duplicate is the DEFAULT outcome rather than an edge case: members are sharded by class, and several
classes legitimately reach the same sink (an SSRF that injection-hunter finds via taint and
server-side-hunter finds via the fetch plane is one defect).

The identity must therefore be the SINK, not the payload. The test that matters most here is the
win32 one: correlate/merge.py normalises with os.path.normpath(...).lower() precisely because
`services\\API\\fetch.py` and `services/api/fetch.py` are one file on this platform, and a
fingerprint that skips that silently fails to collapse the commonest duplicate shape of all.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import swarm_queue as Q  # noqa: E402


@pytest.fixture
def target(tmp_path, monkeypatch):
    monkeypatch.setattr(Q, "swarm_dir", lambda t: tmp_path / "swarm")
    return "t"


# ======================================================== identity is the sink, not the probe ===
def test_the_same_sink_from_two_payloads_is_one_finding(target):
    a = Q.record(target, vuln_class="ssrf", agent="server-side-hunter#2",
                 sink="services/fetch.py:88", effect="listener hit")
    b = Q.record(target, vuln_class="ssrf", agent="injection-hunter#5",
                 sink="services/fetch.py:88", effect="listener hit")
    assert a["finding_id"] == b["finding_id"]
    assert b["agents"] == ["injection-hunter#5", "server-side-hunter#2"]
    assert len(Q.load(target)["findings"]) == 1


def test_win32_case_and_separator_variants_collapse(target):
    """The commonest duplicate shape on this platform. A naive key misses every one of them."""
    Q.record(target, vuln_class="ssrf", agent="a", sink="services/API/fetch.py:88")
    Q.record(target, vuln_class="ssrf", agent="b", sink="services\\api\\fetch.py:88")
    Q.record(target, vuln_class="ssrf", agent="c", sink="services/./api/fetch.py:88")
    findings = Q.load(target)["findings"]
    assert len(findings) == 1, f"{len(findings)} findings for one file - normalisation is missing"
    assert findings[0]["agents"] == ["a", "b", "c"]


def test_a_different_line_is_a_different_finding(target):
    Q.record(target, vuln_class="ssrf", agent="a", sink="services/fetch.py:88")
    Q.record(target, vuln_class="ssrf", agent="a", sink="services/fetch.py:120")
    assert len(Q.load(target)["findings"]) == 2, "dedup collapsed two distinct sinks"


def test_a_different_class_at_one_sink_is_a_different_finding(target):
    Q.record(target, vuln_class="ssrf", agent="a", sink="services/fetch.py:88")
    Q.record(target, vuln_class="path-traversal", agent="a", sink="services/fetch.py:88")
    assert len(Q.load(target)["findings"]) == 2


def test_black_box_findings_key_on_endpoint_and_param(target):
    """url targets have no file:line; endpoint + param + effect carries the identity instead."""
    Q.record(target, vuln_class="xss", agent="xss-hunter#1", endpoint="/search/", param="q",
             effect="alert fired")
    Q.record(target, vuln_class="xss", agent="client-side-hunter#1", endpoint="/search", param="Q",
             effect="Alert Fired")
    assert len(Q.load(target)["findings"]) == 1, "trailing slash or case split one endpoint in two"

    Q.record(target, vuln_class="xss", agent="a", endpoint="/search", param="lang",
             effect="alert fired")
    assert len(Q.load(target)["findings"]) == 2, "a different parameter is a different finding"


def test_a_finding_with_neither_sink_nor_endpoint_is_refused(target):
    with pytest.raises(Q.QueueError, match="sink .* or an endpoint"):
        Q.record(target, vuln_class="ssrf", agent="a", effect="something happened")


# ================================================= a merge keeps the strongest evidence ===
def test_a_runtime_confirmation_outranks_a_read_whichever_lands_first(target):
    Q.record(target, vuln_class="ssrf", agent="a", sink="f.py:1", status="CONFIRMED")
    merged = Q.record(target, vuln_class="ssrf", agent="b", sink="f.py:1",
                      status="code-confirmed")
    assert merged["status"] == "CONFIRMED", "a read downgraded a proven finding"

    Q.record(target, vuln_class="xss", agent="a", sink="g.py:1", status="code-confirmed")
    up = Q.record(target, vuln_class="xss", agent="b", sink="g.py:1", status="CONFIRMED")
    assert up["status"] == "CONFIRMED", "a runtime confirmation failed to upgrade a read"


def test_a_merge_keeps_the_higher_score_and_the_fewer_preconditions(target):
    Q.record(target, vuln_class="ssrf", agent="a", sink="f.py:1", cvss=7.2, preconditions=3)
    m = Q.record(target, vuln_class="ssrf", agent="b", sink="f.py:1", cvss=8.6, preconditions=1)
    assert m["cvss"] == 8.6
    assert m["preconditions"] == 1


def test_a_merge_unions_evidence_and_never_loses_first_seen(target):
    a = Q.record(target, vuln_class="ssrf", agent="a", sink="f.py:1", evidence="e/one.json")
    m = Q.record(target, vuln_class="ssrf", agent="b", sink="f.py:1", evidence="e/two.json")
    assert m["evidence"] == ["e/one.json", "e/two.json"]
    assert m["first_seen"] == a["first_seen"]
    assert m["merged"] == 2


# ============================================================================ ranking ===
def test_confirmed_outranks_unconfirmed_regardless_of_score(target):
    Q.record(target, vuln_class="a", agent="x", sink="f.py:1", status="NEW", cvss=9.8)
    Q.record(target, vuln_class="b", agent="x", sink="f.py:2", status="CONFIRMED", cvss=5.0)
    assert Q.rank(target)[0]["class"] == "b", (
        "an unproven 9.8 outranked a proven 5.0 - the queue would open a lane on a lead")


def test_fewer_preconditions_breaks_a_score_tie(target):
    Q.record(target, vuln_class="stacked", agent="x", sink="f.py:1", status="CONFIRMED",
             cvss=7.1, preconditions=3)
    Q.record(target, vuln_class="clean", agent="x", sink="f.py:2", status="CONFIRMED",
             cvss=7.1, preconditions=0)
    assert Q.rank(target)[0]["class"] == "clean", (
        "a three-precondition finding outranked an unconditional one at the same score - that is "
        "the shape that comes back Infeasible")


def test_the_lane_candidate_is_confirmed_and_top_ranked(target):
    Q.record(target, vuln_class="low", agent="x", sink="f.py:1", status="CONFIRMED", cvss=4.0)
    Q.record(target, vuln_class="high", agent="x", sink="f.py:2", status="CONFIRMED", cvss=9.1)
    Q.record(target, vuln_class="lead", agent="x", sink="f.py:3", status="NEW", cvss=10.0)
    assert Q.lane_candidate(target)["class"] == "high"


def test_no_confirmed_finding_means_no_lane(target):
    Q.record(target, vuln_class="lead", agent="x", sink="f.py:1", status="NEW", cvss=10.0)
    assert Q.lane_candidate(target) is None, "a lane opened on something nothing had proven"
