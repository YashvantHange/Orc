#!/usr/bin/env python3
"""
Regression tests for the delivery gate (reports/gate.py) and the run recorder (evidence/runlog.py).

Run:  .venv/Scripts/python.exe -m pytest tests/test_report_gate.py -q
  or: .venv/Scripts/python.exe tests/test_report_gate.py

Scope note, because it matters: these cover ONLY the deterministic layer. Whether a report's prose is
human, whether a file:line is load-bearing, whether the CVSS metrics were chosen well — none of that
is tested here, because none of it is decided by code. Those are the report-auditor / report-editor
agents' calls, and they are exercised against the defect corpus in work/_selftest/reports/ instead.

What IS tested is everything the gate actually promises:
  * a runlog records a real process and detects one that was edited or hand-written
  * an audit only counts if it PASSes, shows its work, and is bound to the report's current bytes
  * a receipt is issued only on a clean pass, and dies the moment any input changes
  * the unfilled TEMPLATE.md cannot reach a receipt (it passed 9/10 of the old substring gate)
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for _s in (ROOT, ROOT / "static", ROOT / "reports", ROOT / "evidence"):
    sys.path.insert(0, str(_s))

import gate  # noqa: E402
import impact_gate  # noqa: E402
import runlog  # noqa: E402

FID = "ZZTEST01"                    # a finding id no real hunt will ever use
SANDBOX = ROOT / "work" / "_gatetest"


# ------------------------------------------------------------------------------- fixtures ---
def _clean():
    for p in (gate.audit_path(FID, "factual"), gate.audit_path(FID, "editorial"),
              gate.receipt_path(FID), ROOT / "state" / "dup" / f"{FID}.json",
              impact_gate.record_path(FID)):
        if p.exists():
            p.unlink()
    if SANDBOX.exists():
        shutil.rmtree(SANDBOX, ignore_errors=True)
    SANDBOX.mkdir(parents=True, exist_ok=True)


def _report(text: str = "# A short honest title\n\nCVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N 6.5\n") -> Path:
    p = SANDBOX / "report.md"
    p.write_text(text, encoding="utf-8")
    return p


def _ctx(report: Path, **over) -> dict:
    ctx = {"finding_id": FID, "rec": {}, "report_file": report,
           "report_txt": report.read_text(encoding="utf-8"),
           "report_sha": gate.sha256_file(report), "kind": "src", "target": str(SANDBOX)}
    ctx.update(over)
    return ctx


def _audit(report: Path, which: str, verdict: str = "PASS", checked=None, sha=None) -> Path:
    p = gate.audit_path(FID, which)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({
        "finding_id": FID, "verdict": verdict,
        "report_sha256": sha if sha is not None else gate.sha256_file(report),
        "checked": checked if checked is not None else [{"claim": "x", "method": "read it", "result": "match"}],
        "defects": [] if verdict == "PASS" else [
            {"severity": "critical", "location": "H1", "why": "made up"}],
    }), encoding="utf-8")
    return p


# -------------------------------------------------------------------------------- runlog ---
def test_runlog_records_a_real_process():
    _clean()
    runlog.record(str(SANDBOX), FID, 'python -c "print(\'hello-gate\')"')
    doc = runlog.load(str(SANDBOX), FID)
    assert len(doc["runs"]) == 1
    r = doc["runs"][0]
    assert r["exit_code"] == 0
    assert "hello-gate" in r["stdout"]
    assert r["stdout_sha256"] == runlog._h(r["stdout"])
    assert "==" in r["freeze"], "pip freeze should have been captured"


def test_runlog_wants_two_runs():
    _clean()
    runlog.record(str(SANDBOX), FID, 'python -c "print(1)"')
    ok, problems = runlog.verify(runlog.load(str(SANDBOX), FID))
    assert not ok and any("2" in p for p in problems)
    runlog.record(str(SANDBOX), FID, 'python -c "print(1)"')
    ok, _ = runlog.verify(runlog.load(str(SANDBOX), FID))
    assert ok


def test_runlog_detects_edited_output():
    """The bypass this exists to stop: change the recorded stdout to what you wish it had said."""
    _clean()
    for _ in range(2):
        runlog.record(str(SANDBOX), FID, 'python -c "print(\'real\')"')
    p = runlog.runlog_path(str(SANDBOX), FID)
    doc = json.loads(p.read_text(encoding="utf-8"))
    doc["runs"][0]["stdout"] = "PWNED: admin token leaked\n"
    p.write_text(json.dumps(doc), encoding="utf-8")

    ok, problems = runlog.verify(json.loads(p.read_text(encoding="utf-8")))
    assert not ok
    assert any("stdout_sha256 does not match" in x for x in problems)


def test_runlog_rejects_hand_written_entry():
    _clean()
    p = runlog.runlog_path(str(SANDBOX), FID)
    p.write_text(json.dumps({"schema": 1, "runs": [
        {"cmd": "python poc.py", "stdout": "it worked", "stderr": ""},
        {"cmd": "python poc.py", "stdout": "it worked", "stderr": ""}]}), encoding="utf-8")
    ok, problems = runlog.verify(json.loads(p.read_text(encoding="utf-8")))
    assert not ok
    assert any("exit_code" in x for x in problems)
    assert any("hash is missing" in x or "freeze" in x for x in problems)


def test_find_output_matches_only_real_output():
    _clean()
    for _ in range(2):
        runlog.record(str(SANDBOX), FID, 'python -c "print(\'status 403\')"')
    doc = runlog.load(str(SANDBOX), FID)
    assert runlog.find_output(doc, "status 403")[0]
    assert not runlog.find_output(doc, "status 200")[0], "invented output must not match"


def test_freeze_has_catches_a_fabricated_version():
    """The defect class: a pinned version that was never installed."""
    _clean()
    for _ in range(2):
        runlog.record(str(SANDBOX), FID, 'python -c "print(1)"')
    doc = runlog.load(str(SANDBOX), FID)
    assert not runlog.freeze_has(doc, "requests", "2.34.2")[0]


def test_volatile_mask_is_recorded_not_invented():
    _clean()
    for _ in range(2):
        runlog.record(str(SANDBOX), FID, 'python -c "import uuid;print(\'run\', uuid.uuid4().hex)"',
                      volatile=[r"[0-9a-f]{32}"])
    doc = runlog.load(str(SANDBOX), FID)
    assert doc["runs"][0]["volatile"] == [r"[0-9a-f]{32}"]
    # the uuid differs between runs, but the masked line still matches
    assert runlog.find_output(doc, "run " + "a" * 32)[0]


# --------------------------------------------------------------------------- audit binding ---
def test_audit_must_exist():
    _clean()
    ok, why = gate.check_factual_audit(_ctx(_report()))
    assert not ok and "report-auditor" in why


def test_audit_must_pass():
    _clean()
    rp = _report()
    _audit(rp, "factual", verdict="BLOCK")
    ok, why = gate.check_factual_audit(_ctx(rp))
    assert not ok and "BLOCK" in why


def test_audit_pass_with_empty_checked_is_rejected():
    """Hand-writing {"verdict":"PASS"} must not buy anything."""
    _clean()
    rp = _report()
    _audit(rp, "factual", checked=[])
    ok, why = gate.check_factual_audit(_ctx(rp))
    assert not ok and "empty `checked`" in why


def test_audit_is_void_after_the_report_changes():
    """The core anti-bypass property: audit an honest draft, then quietly edit the claims in."""
    _clean()
    rp = _report()
    _audit(rp, "factual")
    assert gate.check_factual_audit(_ctx(rp))[0]

    rp.write_text(rp.read_text(encoding="utf-8") + "\nAnd it also leaks every private key.\n",
                  encoding="utf-8")
    ok, why = gate.check_factual_audit(_ctx(rp))
    assert not ok
    assert "edited after the audit" in why


# ---------------------------------------------------------------------------------- CVSS ---
def test_cvss_score_must_match_the_vector():
    _clean()
    rp = _report("# T\n\n| CVSS 3.1 | 9.8 - CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N |\n")
    ok, why = gate.check_cvss(_ctx(rp))
    assert not ok and "6.5" in why, why


def test_cvss_accepts_a_correct_pair():
    _clean()
    rp = _report("# T\n\n| CVSS 3.1 | 6.5 - CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N |\n")
    ok, why = gate.check_cvss(_ctx(rp))
    assert ok, why


def test_cvss_substring_escape_hatch_is_gone():
    """The old gate passed on the literal text 'cvss:3.1' with no vector behind it."""
    _clean()
    rp = _report("# T\n\nWe scored this with CVSS:3.1 and it is bad.\n")
    ok, _ = gate.check_cvss(_ctx(rp))
    assert not ok


# ------------------------------------------------------------------------------- receipt ---
def _impact_pass(vector: str = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", **over):
    """Record an impact-bar decision. The answers are placeholders; the gate reads the verdict."""
    ans = {"program": "github", "vector": vector, "attacker": "an unauthenticated remote caller",
           "boundary": "unauth -> another tenant's data", "impact": "reads another tenant's rows",
           "marginal_gain": "the same caller can otherwise read only its own rows",
           "gadget": "request -> unchecked id -> row of another tenant, recorded",
           "preconditions": [], "default_config": "yes", "override": ""}
    ans.update(over)
    verdict, blockers, notes = impact_gate.evaluate(ans)
    impact_gate.write(FID, ans, verdict, blockers, notes)
    return verdict


def _pass_everything(rp: Path) -> dict:
    for _ in range(2):
        runlog.record(str(SANDBOX), FID, 'python -c "print(\'ok\')"')
    _audit(rp, "factual")
    _audit(rp, "editorial")
    d = ROOT / "state" / "dup" / f"{FID}.json"
    d.parent.mkdir(parents=True, exist_ok=True)
    d.write_text(json.dumps({"verdict": "NOVEL", "checked_at": gate._now()}), encoding="utf-8")
    _impact_pass()
    return _ctx(rp)


def test_receipt_written_only_on_a_clean_pass():
    _clean()
    rp = _report("# T\n\n| CVSS 3.1 | 6.5 - CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N |\n")
    ctx = _pass_everything(rp)
    results = {}
    for label, fn in gate.checks_for("src"):
        results[label] = fn(ctx)[0]
    assert all(results.values()), results
    gate.write_receipt(ctx, results)
    assert gate.receipt_path(FID).exists()
    assert gate.verify_receipt(FID)[0]


def test_receipt_dies_when_the_report_is_edited():
    """Drill (b): pass the gate, then edit the report and try to ship it."""
    _clean()
    rp = _report("# T\n\n| CVSS 3.1 | 6.5 - CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N |\n")
    ctx = _pass_everything(rp)
    gate.write_receipt(ctx, {k: True for k, _ in gate.checks_for("src")})
    assert gate.verify_receipt(FID)[0]

    rp.write_text(rp.read_text(encoding="utf-8") + "\nnow with extra claims\n", encoding="utf-8")
    ok, why = gate.verify_receipt(FID)
    assert not ok and "has changed since the gate passed" in why


def test_receipt_dies_when_an_audit_is_swapped():
    _clean()
    rp = _report("# T\n\n| CVSS 3.1 | 6.5 - CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N |\n")
    ctx = _pass_everything(rp)
    gate.write_receipt(ctx, {k: True for k, _ in gate.checks_for("src")})
    _audit(rp, "factual", checked=[{"claim": "different", "method": "m", "result": "r"}])
    ok, why = gate.verify_receipt(FID)
    assert not ok and "factual audit changed" in why


def test_missing_receipt_reports_missing():
    _clean()
    ok, why = gate.verify_receipt(FID)
    assert not ok and "no gate receipt" in why


# ------------------------------------------------------------------------ the headline case ---
def test_unfilled_template_cannot_reach_a_receipt():
    """The old substring gate scored the untouched template 9/10. It must now score 0 on content.

    This is the single most important test in the file: it is the difference between a gate that
    describes quality and a gate that requires it.
    """
    _clean()
    tpl = ROOT / "reports" / "TEMPLATE.md"
    assert tpl.exists()
    rp = SANDBOX / "report.md"
    rp.write_text(tpl.read_text(encoding="utf-8"), encoding="utf-8")
    ctx = _ctx(rp)

    failed = [label for label, fn in gate.checks_for("src") if not fn(ctx)[0]]
    # everything except "Report exists" (the file is real, it is just empty of facts)
    assert "PoC executed" in failed
    assert "Factual audit" in failed
    assert "Editorial audit" in failed
    assert "Duplicate check" in failed
    assert "CVSS" in failed
    assert not gate.receipt_path(FID).exists()


# --------------------------------------------------------------------------- impact bar ---
# These encode three real vendor closures. Each had a runtime PoC, two cold audits and a delivery
# receipt, and each was still closed "not severe enough for us to track it as a security bug":
# FIL-004 and FIL-005 (CI-guard defects, 2026-09-04) and SHAKA-003 (a CVSS 3.8 prototype-pollution
# primitive, no demonstrated gadget, three stacked preconditions, 2026-09-08). Every other check in
# gate.py passed all three, which is the whole reason this one exists.
def test_impact_bar_blocks_below_the_severity_floor():
    _clean()
    assert _impact_pass(vector="CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N") == "BLOCK"  # 3.8
    assert not impact_gate.cleared(FID)[0]


def test_impact_bar_blocks_a_primitive_with_no_gadget():
    """SHAKA-003's own sentence: the PoC proves the primitive and stops there."""
    _clean()
    assert _impact_pass(gadget="") == "BLOCK"
    assert "gadget" in impact_gate.load(FID)["blockers"][0]


def test_impact_bar_blocks_three_stacked_preconditions():
    _clean()
    assert _impact_pass(preconditions=["app sets castReceiverAppId",
                                       "viewer is actively casting",
                                       "attacker controls the receiver"]) == "BLOCK"


def test_impact_bar_requires_the_default_configuration_answer():
    """The question that decided SHAKA-C8-001 cannot be skipped by not asking it."""
    _clean()
    assert _impact_pass(default_config="") == "BLOCK"
    assert "default-config" in impact_gate.load(FID)["blockers"][0]


def test_non_default_configuration_blocks_at_two_preconditions():
    """SHAKA-C8-001 self-scored 7.1 C:H, stacked three conditions and came back P4/S4 Infeasible.
    Non-default configuration is the heaviest of them, so two conditions including it is the same
    shape as three ordinary ones — and two ordinary ones is still fine."""
    _clean()
    assert _impact_pass(default_config="no",
                        preconditions=["app configures drm.servers[org.w3.clearkey]",
                                       "attacker can influence the manifest"]) == "BLOCK"
    assert "non-default configuration" in impact_gate.load(FID)["blockers"][0]
    _clean()
    assert _impact_pass(default_config="yes",
                        preconditions=["attacker can influence the manifest",
                                       "the victim plays the stream"]) == "PASS"


def test_non_default_configuration_is_not_counted_twice():
    """An answer of 'no' plus a precondition that already says 'configures' is ONE condition, not
    two — the message has to be arithmetic a triager would accept."""
    _clean()
    assert _impact_pass(default_config="no",
                        preconditions=["app configures a custom handler"]) == "PASS"


def test_override_on_a_precondition_block_reports_the_observed_record():
    """The operator may still override, but not without being told the record: SHAKA-C8-001 was
    overridden on a five-point rationale and closed P4/S4 Infeasible anyway."""
    _clean()
    assert _impact_pass(default_config="no",
                        preconditions=["app configures X", "attacker influences the manifest"],
                        override="my call") == "PASS_OVERRIDDEN"
    notes = " ".join(impact_gate.load(FID)["notes"])
    assert "OVERRIDE RECORD" in notes and "SHAKA-C8-001" in notes


def test_impact_bar_blocks_the_two_dead_classes():
    _clean()
    assert _impact_pass(ci_guard=True) == "BLOCK"
    _clean()
    assert _impact_pass(dev_tool=True) == "BLOCK"


def test_impact_bar_passes_a_real_finding_and_records_the_override():
    _clean()
    assert _impact_pass() == "PASS"
    ok, why = impact_gate.cleared(FID)
    assert ok and "PASS" in why
    # Only the user may override, and their words are kept verbatim in the decision.
    assert _impact_pass(vector="CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",
                        override="file it anyway, my call") == "PASS_OVERRIDDEN"
    d = impact_gate.load(FID)
    assert impact_gate.cleared(FID)[0] and d["answers"]["override"] == "file it anyway, my call"
    assert d["blockers"], "an overridden decision must still record what it walked past"


def test_impact_decision_goes_stale_when_the_vector_changes():
    """A decision made on one vector cannot license a report that now claims another."""
    _clean()
    _impact_pass()
    ok, why = impact_gate.cleared(FID, "CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N = 2.0 (Low)")
    assert not ok and "re-run" in why


def test_delivery_gate_refuses_without_an_impact_decision():
    """The point of the check: everything else passes and the receipt is still withheld."""
    _clean()
    rp = _report("# T\n\n| CVSS 3.1 | 6.5 - CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N |\n")
    ctx = _pass_everything(rp)
    impact_gate.record_path(FID).unlink()
    results = {label: fn(ctx)[0] for label, fn in gate.checks_for("src")}
    assert results["Impact bar"] is False
    assert all(v for k, v in results.items() if k != "Impact bar"), results


def _teardown():
    _clean()
    if SANDBOX.exists():
        shutil.rmtree(SANDBOX, ignore_errors=True)


if __name__ == "__main__":
    fns = [(n, f) for n, f in sorted(globals().items())
           if n.startswith("test_") and callable(f)]
    bad = 0
    for n, f in fns:
        try:
            f()
            print(f"  ok   {n}")
        except Exception as e:                              # noqa: BLE001
            bad += 1
            print(f"  FAIL {n}: {type(e).__name__}: {e}")
    _teardown()
    print(f"\n{len(fns) - bad}/{len(fns)} passed")
    sys.exit(1 if bad else 0)

# --- Gap 1: quoted output must come from a recorded run ---

def _quoted_ctx(report_txt, *runs):
    return {
        "report_txt": report_txt,
        "runlog": {"runs": [{"stdout": r, "stderr": ""} for r in runs]},
    }


def test_quoted_output_present_passes():
    run = "[HOST] GET /a?token=SECRET\n[HOST] GET /b\nRESULT: CONFIRMED\n"
    report = "Evidence:\n\n```\n[HOST] GET /a?token=SECRET\n[HOST] GET /b\n```\n"
    ok, msg = gate.check_quoted_output(_quoted_ctx(report, run))
    assert ok, msg


def test_stale_runlog_blocks():
    """The real regression: the report quotes a case the recorded run never exercised."""
    run = "[HOST] GET /a?token=SECRET\n[HOST] GET /b\n"
    report = (
        "Evidence:\n\n```\n"
        "[HOST] GET /a?token=SECRET\n"
        "[HOST] GET /legacy-init.mp4?token=SECRET\n"  # never run
        "```\n"
    )
    ok, msg = gate.check_quoted_output(_quoted_ctx(report, run))
    assert not ok
    assert "do not appear in any recorded run" in msg
    assert "legacy-init" in msg


def test_source_fences_are_not_treated_as_output():
    """A ```js patch or ```xml snippet is source, not captured output."""
    run = "[HOST] GET /a\n"
    report = (
        "Root cause:\n\n```js\n"
        "    this.lastManifestQueryParams_ = url.searchParams.toString();\n"
        "```\n\n"
        "Repro:\n\n```xml\n<RequestParam useMPDUrlQuery=\"true\"/>\n```\n"
    )
    ok, msg = gate.check_quoted_output(_quoted_ctx(report, run))
    assert ok, msg


def test_no_quoted_output_passes():
    ok, msg = gate.check_quoted_output(_quoted_ctx("No fences here at all.\n", "[HOST] GET /a\n"))
    assert ok
    assert "no captured-output blocks" in msg


def test_output_may_come_from_any_recorded_run():
    """Counts vary between runs; a line present in run 2 is still evidenced."""
    report = "```\n[HOST] GET /c\n```\n"
    ok, msg = gate.check_quoted_output(_quoted_ctx(report, "[HOST] GET /a\n", "[HOST] GET /c\n"))
    assert ok, msg


def test_missing_runlog_blocks():
    ok, msg = gate.check_quoted_output({"report_txt": "```\nx\n```\n"})
    assert not ok


def test_empty_recorded_output_blocks():
    ok, msg = gate.check_quoted_output(_quoted_ctx("```\n[HOST] GET /a\n```\n", ""))
    assert not ok
    assert "captured no output" in msg
