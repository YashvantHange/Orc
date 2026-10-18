#!/usr/bin/env python3
"""
gate.py — the delivery gate. Verifies the EVIDENCE CHAIN behind a report; never grades the report.

The distinction is the whole design. Judging a report — is the prose human, is this file:line
load-bearing, is the CVSS vector the right one — needs reading and reasoning, and a script that tries
it produces confident nonsense. That work belongs to two agents:

    report-auditor   cold factual audit  -> state/audit/<ID>.factual.json
    report-editor    presentation/voice  -> state/audit/<ID>.editorial.json

What a script CAN do without ever being wrong is check facts about files: did a process really run,
does this hash match those bytes, is the audit bound to the report as it stands right now. That is all
this module does. Every check below is a yes/no about the filesystem, not an opinion about the finding.

So the gate answers one question: **has the judging actually happened, by agents that read this exact
version of this report, on top of a PoC that actually ran?** If yes it issues a receipt at
state/gate/<ID>.json. Edit the report by one byte afterwards and the receipt, plus both audits, go
stale — deliberately, because a changed report has not been reviewed.

  python reports/gate.py <finding-id> [--json]
  hunt validate-report <finding-id>
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for _sub in ("static", "evidence", "reports"):
    sys.path.insert(0, str(ROOT / _sub))

GATE_VERSION = 1
DUP_MAX_AGE_DAYS = 14


# ------------------------------------------------------------------------------- helpers ---
def sha256_file(p: Path) -> str:
    try:
        return "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest()
    except OSError:
        return ""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _age_days(stamp: str) -> float:
    try:
        t = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - t).total_seconds() / 86400
    except (ValueError, TypeError):
        return 1e9


def ledger() -> list:
    p = ROOT / "state" / "ledger.json"
    try:
        return json.loads(p.read_text(encoding="utf-8")).get("findings", [])
    except (OSError, json.JSONDecodeError):
        return []


def record(finding_id: str) -> dict:
    return next((f for f in ledger() if f.get("finding_id") == finding_id), {})


def report_path(rec: dict) -> Path | None:
    rp = rec.get("report_path")
    return (ROOT / rp) if rp else None


def audit_path(finding_id: str, which: str) -> Path:
    return ROOT / "state" / "audit" / f"{finding_id}.{which}.json"


def receipt_path(finding_id: str) -> Path:
    return ROOT / "state" / "gate" / f"{finding_id}.json"


# -------------------------------------------------------------------------------- checks ---
# Each returns (ok: bool, detail: str). Facts only.

def check_report_exists(ctx: dict) -> tuple[bool, str]:
    p = ctx.get("report_file")
    if not p:
        return False, "no report_path in the ledger for this finding"
    if not p.exists():
        return False, f"report_path points at a file that does not exist: {p}"
    if not p.read_text(encoding="utf-8", errors="replace").strip():
        return False, "the report file is empty"
    return True, f"{p.relative_to(ROOT)} ({ctx['report_sha'][:23]}...)"


def check_poc_executed(ctx: dict) -> tuple[bool, str]:
    """A PoC that was never run cannot have produced the output the report quotes."""
    import runlog
    target = ctx["target"]
    if not target:
        return False, "no target recorded on the finding; cannot locate the runlog"
    doc = runlog.load(target, ctx["finding_id"])
    if not doc:
        return False, (f"no runlog at work/<slug>/evidence/{ctx['finding_id']}/runlog.json - "
                       f"run the PoC through `hunt poc-run` (twice)")
    ctx["runlog"] = doc
    ok, problems = runlog.verify(doc)
    if not ok:
        return False, "; ".join(problems)
    n = len(doc.get("runs", []))
    return True, f"{n} recorded run(s), hashes consistent, tree clean"


# --- Gap 1 (RULES.md) ---------------------------------------------------------------------------
# Every other check here verifies that a claim in the report is TRUE. None verified that output the
# report QUOTES came from a recorded execution. A PoC can grow a case while the runlog still holds
# the previous run, and the report then quotes lines its own script never produced. That happened on
# a delivered-ready report and was caught by hand, one step before the auditors.

# Lines inside a fence that are prose, headings or diff/code rather than captured output. A quoted
# fence is only checked when it looks like program output, so a report may still show a proposed
# patch or an XML snippet without the gate demanding it appear in a runlog.
_OUTPUT_HINT = re.compile(r"^\s*(?:\[|\$|>|#\s|PASS|FAIL|OK\b|ok\s|GET |POST |HTTP/|Traceback|\w+:\s)")


def _fenced_blocks(md: str) -> list[tuple[str, str]]:
    """Return (info_string, body) for every fenced block in the report."""
    out = []
    for m in re.finditer(r"^```([^\n]*)\n(.*?)^```", md, re.S | re.M):
        out.append((m.group(1).strip().lower(), m.group(2)))
    return out


def _looks_like_output(info: str, body: str) -> bool:
    # An explicitly language-tagged fence is source, not captured output.
    if info in {"js", "ts", "py", "python", "java", "go", "rust", "c", "cpp", "xml", "html",
                "json", "yaml", "yml", "diff", "patch", "sql"}:
        return False
    lines = [l for l in body.split("\n") if l.strip()]
    if not lines:
        return False
    return sum(bool(_OUTPUT_HINT.match(l)) for l in lines) >= max(2, len(lines) // 2)


def check_quoted_output(ctx: dict) -> tuple[bool, str]:
    """Output quoted in the report must appear in a recorded run.

    Guards against a report that quotes a stale runlog, a hand-edited transcript, or output from a
    PoC revision that was never re-run.
    """
    doc = ctx.get("runlog")
    if not doc:
        return False, "no runlog loaded; the PoC-executed check must pass first"

    recorded = "\n".join(
        (r.get("stdout") or "") + "\n" + (r.get("stderr") or "")
        for r in doc.get("runs", [])
    )
    if not recorded.strip():
        return False, "the recorded runs captured no output to compare the report against"

    checked = missing = 0
    first_missing = []
    for info, body in _fenced_blocks(ctx["report_txt"]):
        if not _looks_like_output(info, body):
            continue
        for line in (l.rstrip() for l in body.split("\n")):
            if not line.strip():
                continue
            checked += 1
            if line.strip() not in recorded:
                missing += 1
                if len(first_missing) < 3:
                    first_missing.append(line.strip()[:90])

    if not checked:
        return True, "no captured-output blocks quoted in the report"
    if missing:
        return False, (
            f"{missing} of {checked} quoted output line(s) do not appear in any recorded run - "
            f"re-run the PoC so the report quotes a real execution. First: "
            + " | ".join(first_missing)
        )
    return True, f"{checked} quoted output line(s) all present in the recorded runs"


def _check_audit(ctx: dict, which: str, agent: str) -> tuple[bool, str]:
    """The audit must exist, PASS, show its work, and be bound to the CURRENT report bytes."""
    p = audit_path(ctx["finding_id"], which)
    if not p.exists():
        return False, f"no {which} audit - run the `{agent}` agent; expected {p.relative_to(ROOT)}"
    try:
        a = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return False, f"{p.name} is not valid JSON ({e})"

    ctx[f"{which}_audit_sha"] = sha256_file(p)
    verdict = str(a.get("verdict", "")).upper()
    if verdict != "PASS":
        defects = a.get("defects") or []
        blocking = [d for d in defects
                    if str(d.get("severity", "")).lower() in ("critical", "major")]
        head = "; ".join(f"[{d.get('severity')}] {d.get('location', '?')}: {d.get('why', '')[:90]}"
                         for d in blocking[:3])
        return False, (f"{agent} returned {verdict or 'no verdict'} - "
                       f"{len(blocking)} blocking defect(s). {head}")

    if not (a.get("checked") or []):
        return False, (f"{agent} returned PASS with an empty `checked` list - a verdict with no "
                       f"recorded verification is not an audit")

    bound = a.get("report_sha256", "")
    if bound != ctx["report_sha"]:
        return False, (f"{which} audit was made against different bytes than the report now has "
                       f"(audit {bound[:23]}... vs file {ctx['report_sha'][:23]}...) - the report "
                       f"was edited after the audit; re-run `{agent}`")
    return True, f"PASS, {len(a['checked'])} claim(s) checked, bound to current bytes"


def check_factual_audit(ctx: dict) -> tuple[bool, str]:
    return _check_audit(ctx, "factual", "report-auditor")


def check_editorial_audit(ctx: dict) -> tuple[bool, str]:
    return _check_audit(ctx, "editorial", "report-editor")


def check_duplicate(ctx: dict) -> tuple[bool, str]:
    """A real dup-check artifact, recent enough to mean anything. Not the word 'duplicate'."""
    p = ROOT / "state" / "dup" / f"{ctx['finding_id']}.json"
    if not p.exists():
        rec = ctx["rec"]
        if rec.get("dup_verdict") and rec.get("dup_checked_at"):
            age = _age_days(rec["dup_checked_at"])
            if age > DUP_MAX_AGE_DAYS:
                return False, f"ledger dup check is {age:.0f} days old (max {DUP_MAX_AGE_DAYS}); re-run `hunt dup`"
            return True, f"ledger dup_verdict={rec['dup_verdict']} ({age:.0f}d old)"
        return False, (f"no dup artifact at {p.relative_to(ROOT)} and no dated dup_verdict in the "
                       f"ledger - run `hunt dup <owner/repo> --query ...`")
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False, f"{p.name} is not valid JSON"
    age = _age_days(d.get("checked_at", ""))
    if age > DUP_MAX_AGE_DAYS:
        return False, f"dup check is {age:.0f} days old (max {DUP_MAX_AGE_DAYS}); re-run `hunt dup`"
    return True, f"verdict={d.get('verdict', '?')}, {age:.1f}d old"


def check_impact_bar(ctx: dict) -> tuple[bool, str]:
    """Is there a recorded decision that this finding clears the destination program's bar?

    This is the one check here that is about the finding rather than the paperwork, and it is still
    a filesystem fact: impact_gate.py made the judgement and wrote it down; this asks whether it did,
    and whether it was made on the vector the report now carries. Added after three fully-proven,
    fully-audited reports came back "not severe enough for us to track it as a security bug" -
    FIL-004, FIL-005, SHAKA-003. Every other check in this file would have passed all three.
    """
    import impact_gate
    return impact_gate.cleared(ctx["finding_id"], ctx["rec"].get("cvss") or "")


def check_cvss(ctx: dict) -> tuple[bool, str]:
    """Arithmetic, not judgement: the vector must parse and its score must match what's printed.

    Whether the METRICS are the right ones is report-auditor's call - it re-derives them by reading.
    """
    import cvss as _cvss
    txt = ctx["report_txt"]
    vec_re = re.compile(r"CVSS:3\.1/(?:[A-Z]+:[A-Z]+/?)+")
    vectors = vec_re.findall(txt)
    ledger_vec = (ctx["rec"].get("cvss") or "").strip()
    if not vectors and not ledger_vec:
        return False, "no CVSS:3.1 vector in the report or the ledger"

    vec = vectors[0] if vectors else ledger_vec
    try:
        score, sev, canon = _cvss.score_vector(vec)
    except ValueError as e:
        return False, f"vector does not parse: {vec} ({e})"

    if ledger_vec and vectors:
        try:
            if _cvss.score_vector(ledger_vec)[2] != canon:
                return False, f"report vector {vec} != ledger vector {ledger_vec}"
        except ValueError:
            return False, f"ledger holds an unparseable vector: {ledger_vec}"

    # Whatever score the report prints beside a vector must be the one that vector produces.
    # Strip the vector text first, or "CVSS:3.1" donates a stray "3.1" to every line.
    printed = set()
    for line in txt.splitlines():
        if "CVSS" not in line.upper():
            continue
        printed |= set(re.findall(r"\b(\d{1,2}\.\d)\b", vec_re.sub(" ", line)))
    if printed and f"{score:.1f}" not in printed:
        return False, (f"{canon} scores {score:.1f}, but the report prints "
                       f"{', '.join(sorted(printed))} beside a CVSS vector - fix whichever is wrong")
    return True, f"{canon} = {score:.1f} ({sev})"


def check_transcript(ctx: dict) -> tuple[bool, str]:
    """Live targets: cited T##### ids exist and their response hashes match the bundle."""
    from live_checks import transcript_ok
    return transcript_ok(ctx["rec"], ctx["report_txt"])


def check_scope_auth(ctx: dict) -> tuple[bool, str]:
    from live_checks import scope_auth_ok
    return scope_auth_ok(ctx["rec"], ctx["report_txt"])


CHECKS_COMMON = [
    ("Report exists", check_report_exists),
    ("Impact bar", check_impact_bar),
    ("PoC executed", check_poc_executed),
    ("Quoted output", check_quoted_output),
    ("Factual audit", check_factual_audit),
    ("Editorial audit", check_editorial_audit),
    ("Duplicate check", check_duplicate),
    ("CVSS", check_cvss),
]
CHECKS_LIVE = [
    ("Evidence transcript", check_transcript),
    ("Scope authorization", check_scope_auth),
]


def checks_for(kind: str) -> list:
    if kind == "url":
        # A live host has no commit and no local PoC process, so the runlog is not the anchor -
        # the transcript is, and it is hash-verified against the bundle. Same rigour, different proof.
        return [c for c in CHECKS_COMMON if c[0] != "PoC executed"] + CHECKS_LIVE
    if kind == "grey":
        return CHECKS_COMMON + CHECKS_LIVE
    return CHECKS_COMMON


# ------------------------------------------------------------------------------- receipt ---
def write_receipt(ctx: dict, results: dict) -> Path:
    p = receipt_path(ctx["finding_id"])
    p.parent.mkdir(parents=True, exist_ok=True)
    runlog_file = ""
    if ctx.get("runlog"):
        import runlog as _rl
        runlog_file = str(_rl.runlog_path(ctx["target"], ctx["finding_id"]))
    p.write_text(json.dumps({
        "gate_version": GATE_VERSION,
        "finding_id": ctx["finding_id"],
        "issued_at": _now(),
        "report_path": str(ctx["report_file"].relative_to(ROOT)),
        "report_sha256": ctx["report_sha"],
        "runlog_path": runlog_file,
        "runlog_sha256": sha256_file(Path(runlog_file)) if runlog_file else "",
        # Hash the audits from disk rather than from ctx. Reading them out of ctx only works when a
        # check happened to populate it, and a receipt that silently records "" for an audit is a
        # receipt that will not notice the audit being swapped afterwards.
        "factual_audit_sha256": sha256_file(audit_path(ctx["finding_id"], "factual")),
        "editorial_audit_sha256": sha256_file(audit_path(ctx["finding_id"], "editorial")),
        "target_kind": ctx["kind"],
        "checks": {k: "pass" for k in results},
    }, indent=2), encoding="utf-8")
    return p


def verify_receipt(finding_id: str) -> tuple[bool, str]:
    """Is there a receipt that still describes the report as it exists right now?

    Recomputes every hash rather than trusting the receipt's own copy - a receipt is a claim, and the
    files are the fact. This is what the delivery hook calls.
    """
    p = receipt_path(finding_id)
    if not p.exists():
        return False, f"no gate receipt for {finding_id} - run `hunt validate-report {finding_id}`"
    try:
        r = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False, f"{p.name} is not valid JSON"
    if r.get("gate_version") != GATE_VERSION:
        return False, (f"receipt was issued by gate v{r.get('gate_version')}, this is v{GATE_VERSION} "
                       f"- re-run the gate")

    rf = ROOT / r.get("report_path", "")
    if not rf.exists():
        return False, f"the receipt names a report that no longer exists: {r.get('report_path')}"
    live = sha256_file(rf)
    if live != r.get("report_sha256"):
        return False, (f"{rf.name} has changed since the gate passed - the audits described different "
                       f"bytes. Re-run report-auditor, report-editor, then the gate.")

    for label, key, path in (
        ("factual audit", "factual_audit_sha256", audit_path(finding_id, "factual")),
        ("editorial audit", "editorial_audit_sha256", audit_path(finding_id, "editorial")),
    ):
        want = r.get(key, "")
        if want:
            if not path.exists():
                return False, f"the {label} named by the receipt is gone: {path.name}"
            if sha256_file(path) != want:
                return False, f"the {label} changed after the gate passed - re-run the gate"
    rl = r.get("runlog_path", "")
    if rl and r.get("runlog_sha256"):
        if not Path(rl).exists():
            return False, "the runlog named by the receipt is gone"
        if sha256_file(Path(rl)) != r["runlog_sha256"]:
            return False, "the runlog changed after the gate passed - re-run the gate"
    return True, f"receipt valid, issued {r.get('issued_at')}"


# ----------------------------------------------------------------------------------- run ---
def run(finding_id: str) -> tuple[int, dict, dict]:
    rec = record(finding_id)
    rf = report_path(rec)
    txt = rf.read_text(encoding="utf-8", errors="replace") if (rf and rf.exists()) else ""

    kind = rec.get("target_kind") or ""
    if not kind:
        try:
            sys.path.insert(0, str(ROOT))
            import hunt
            kind = hunt.load_profile(rec.get("target_url") or rec.get("repo") or "").get("kind", "src")
        except Exception:                                    # noqa: BLE001
            kind = "src"

    ctx = {
        "finding_id": finding_id,
        "rec": rec,
        "report_file": rf,
        "report_txt": txt,
        "report_sha": sha256_file(rf) if (rf and rf.exists()) else "",
        "kind": kind,
        "target": rec.get("target") or rec.get("repo") or rec.get("target_url") or "",
    }

    results, details = {}, {}
    for label, fn in checks_for(kind):
        try:
            ok, detail = fn(ctx)
        except Exception as e:                               # noqa: BLE001
            ok, detail = False, f"check raised {type(e).__name__}: {e}"
        results[label], details[label] = ok, detail

    failed = [k for k, v in results.items() if not v]
    if not failed:
        write_receipt(ctx, results)
    return (1 if failed else 0), results, {"details": details, "ctx": ctx}


def main(argv: list | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("usage: gate.py <finding-id> [--json]", file=sys.stderr)
        return 2
    fid = argv[0]
    code, results, extra = run(fid)
    details, ctx = extra["details"], extra["ctx"]

    if "--json" in argv:
        print(json.dumps({"finding_id": fid, "kind": ctx["kind"], "pass": code == 0,
                          "checks": {k: {"ok": v, "detail": details[k]} for k, v in results.items()}},
                         indent=2))
        return code

    print(f"delivery gate {fid}  (target kind: {ctx['kind']})")
    for k, v in results.items():
        print(f"  [{'x' if v else ' '}] {k}")
        if details[k]:
            print(f"        {details[k]}")

    if code == 0:
        print(f"\nPASS - receipt written to {receipt_path(fid).relative_to(ROOT)}")
        print("  The report may be delivered. Any edit to it voids this receipt.")
    else:
        failed = [k for k, v in results.items() if not v]
        print(f"\nBLOCKED - {len(failed)} check(s) failed: {', '.join(failed)}")
        print("  No receipt issued. This report must not be delivered or submitted.")
    return code


if __name__ == "__main__":
    sys.exit(main())
