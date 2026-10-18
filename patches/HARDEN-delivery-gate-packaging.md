# Harden the delivery gate: packaging and destination-form rules

**Apply this by hand.** `tools/hooks/**` is write-protected from the agent, which is correct — an agent
must not be able to edit the machinery that constrains it. That protection is also why these rules
cannot be self-applied and must be installed by you.

## What went wrong, twice, on 2026-09-09

Both failures were of rules that were **already written down** and enforced only by intention.

1. **SHAKA-007 was left in `work/` as a loose `ISSUE-DRAFT.md`.** The rule
   (`report-folder-with-poc-attached`) says every finding ships as its own folder under `reports/`,
   "NOT `work/<slug>/...`". Nothing caught it, because `_hookutil.is_report()` only matches paths under
   `reports/` — a deliverable written to `work/` is invisible to the entire gate. The rationalisation
   was "this goes to a GitHub issue, not the VRP, so it isn't a report". The rule keys on *delivered
   finding*, not on *destination*.

2. **The destination form was never resolved.** `shaka-project/shaka-player` files bugs through
   `.github/ISSUE_TEMPLATE/bug.yaml` — a GitHub issue **form** with 14 discrete fields and five
   required dropdowns with fixed option values. The finding was written as one markdown blob, which
   cannot be pasted into that form at all. The shape was inferred from how an existing issue *renders*,
   which is the form's output, not its input. `external-portal-form-fields-gate` already required
   resolving the real form first.

A third, smaller one: `submission-fields/` briefly contained a file whose body was an instruction
("TICK THE BOX…") rather than a value, and an invented `.DROPDOWN.` filename convention inconsistent
with the existing one. A field file must hold the value and nothing else.

## Patch — `tools/hooks/pre_delivery_gate.py`

Add above `def main()`:

```python
# Names that mean "this text is meant for someone outside this machine". A file called any of these
# is a deliverable no matter which directory it was written into.
DELIVERABLE_NAMES = ("issue-draft", "issue", "report", "advisory", "disclosure", "submission",
                     "finding", "writeup", "write-up", "how-to-file", "howtofile")

# Ledger states that mean a finding is real and therefore owes a packaged folder.
DELIVERABLE_STATUS = ("CONFIRMED", "REPORTED", "SUBMITTED")

# Text that has no business inside a field file: a field file is a paste-ready VALUE, not guidance.
INSTRUCTION_MARKERS = ("tick the box", "paste this", "paste into", "select the", "dropdown",
                       "must be selected", "do not paste", "see how-to-file")


def stranded_deliverables() -> list:
    """Deliverable-looking markdown sitting outside reports/. (Failure 1.)"""
    out = []
    work = ROOT / "work"
    if not work.is_dir():
        return out
    for p in work.rglob("*.md"):
        parts = {x.lower() for x in p.parts}
        if "node_modules" in parts or ".git" in parts:
            continue
        if any(k in p.stem.lower() for k in DELIVERABLE_NAMES):
            try:
                rel = p.relative_to(ROOT)
            except ValueError:
                rel = p
            out.append(str(rel).replace("\\", "/"))
    return sorted(out)


def unpackaged_findings() -> list:
    """Ledger findings that are real but have no report folder under reports/. (Failure 1, other side.)"""
    import json
    out = []
    try:
        led = json.loads((ROOT / "state" / "ledger.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return out
    for rec in led.get("findings", []):
        fid = str(rec.get("finding_id") or "")
        status = str(rec.get("status") or "").upper()
        if not fid or status not in DELIVERABLE_STATUS:
            continue
        rp = str(rec.get("report_path") or "").replace("\\", "/")
        if rp.startswith("reports/") and (ROOT / rp).exists():
            continue
        if is_waived(fid, ""):          # recorded but explicitly not being delivered
            continue
        out.append(f"{fid} (status {status}): report_path={rp or '(none)'}")
    return out


def folder_shape_problems() -> list:
    """Structural completeness of every report folder.

    Failure 2 was that the destination's real form was never resolved. The fix is README.txt: it must
    name the destination and cite WHERE the field list came from, so the next session can re-check it
    rather than trust it. See reports/SHAKA-005-*/submission-fields/README.txt for the established
    shape - it also records why a copy of the report body is deliberately NOT kept in this folder.
    """
    out = []
    rdir = ROOT / "reports"
    if not rdir.is_dir():
        return out
    for folder in sorted(p for p in rdir.iterdir() if p.is_dir()):
        name = folder.name
        if not any(m.name != "HOW-TO-FILE.md" for m in folder.glob("*.md")):
            continue                                   # not a finding folder
        if not (folder / "HOW-TO-FILE.md").exists():
            out.append(f"reports/{name}: no HOW-TO-FILE.md")
        if not (folder / "poc").is_dir():
            out.append(f"reports/{name}: no poc/ directory")
        sf = folder / "submission-fields"
        if not sf.is_dir():
            out.append(f"reports/{name}: no submission-fields/")
            continue
        if not (sf / "README.txt").exists():
            out.append(f"reports/{name}: submission-fields/README.txt missing - it must name the "
                       f"destination and cite where the field list came from (URL or repo path of "
                       f"the form definition)")
        body = folder / f"{name}.md"
        for p in sorted(sf.iterdir()):
            if not p.is_file() or p.name == "README.txt":
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
            # A duplicate of the report body drifts out of sync with the receipt. This has happened.
            if body.exists() and len(text) > 2000 and text[:200] in body.read_text(
                    encoding="utf-8", errors="replace"):
                out.append(f"reports/{name}: submission-fields/{p.name} looks like a copy of the "
                           f"report body. The receipt binds the report's sha256; a second copy can "
                           f"drift without anything noticing. Paste from the report itself")
            low = text.lower()
            for marker in INSTRUCTION_MARKERS:
                if marker in low:
                    out.append(f"reports/{name}: submission-fields/{p.name} contains instruction "
                               f"text (\"{marker}\"). A field file is a paste-ready value only; "
                               f"guidance belongs in README.txt or HOW-TO-FILE.md")
                    break
    return out
```

Then insert at the **top** of `main()`, before the existing `reports = [...]` line:

```python
    packaging = []
    for rel in stranded_deliverables():
        packaging.append(
            f"{rel}: a deliverable write-up outside reports/. Move it to "
            f"reports/<ID>-<product>-<slug>/ with its poc/, or rename it if it is not a deliverable")
    for row in unpackaged_findings():
        packaging.append(f"{row} - no report folder under reports/")
    packaging.extend(folder_shape_problems())
    if packaging:
        lines = "\n".join(f"  - {p}" for p in packaging)
        return emit({
            "decision": "block",
            "reason": (
                f"Packaging or destination-form rules are not satisfied. HARD RULES, all of which have "
                f"been broken before:\n"
                f"  1. Every finding ships as its own folder under the top-level reports/ - NOT "
                f"work/<slug>/... The workdir is scratch. This applies to EVERY destination: a public "
                f"GitHub issue is a delivery as much as a VRP submission.\n"
                f"  2. Every finding folder carries the report .md, HOW-TO-FILE.md, poc/ and "
                f"submission-fields/.\n"
                f"  3. The destination's REAL form must be resolved before the folder passes, and "
                f"recorded in submission-fields/FORM.json (destination, source, resolved_at, fields). "
                f"Never infer a form's shape from how a submitted item renders.\n"
                f"  4. Each field file holds a paste-ready value and nothing else.\n\n"
                f"{lines}\n\n"
                f"If the finding is genuinely not being delivered, record that with "
                f"`python tools/hooks/waive.py <ID> --reason \"...\"`."),
        })
```

## Why FORM.json is the load-bearing part

Checks 1 and 2 are hygiene — they catch a missing folder. Only check 3 catches a folder that is
*complete but aimed at the wrong form*, which is the more expensive failure, because everything looks
finished. It cannot be satisfied without going and reading the destination's real field definition,
and it records where that definition came from so the next session can re-check it rather than trust it.

## Also wire in the submission-fields contract

`tools/check_submission_fields.py` already exists and is runnable — it enforces the fixed five-file
packet and, critically, refuses a packet on an availability-only finding. Call it from the same hook so
it cannot be forgotten. Add to `main()`, immediately after the `packaging` block:

```python
    import subprocess
    r = subprocess.run([sys.executable, str(ROOT / "tools" / "check_submission_fields.py")],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return emit({
            "decision": "block",
            "reason": ("The submission-fields contract is not satisfied. A packet exists only for a "
                       "finding going to a VRP, it is exactly five files, and it must never exist for "
                       "an availability-only finding.

" + r.stdout.strip()),
        })
```

## Verify after applying

```bash
python tools/hooks/pre_delivery_gate.py < /dev/null      # expect: clean, or a specific block

mkdir -p work/_gatetest && echo x > work/_gatetest/ISSUE-DRAFT.md
python tools/hooks/pre_delivery_gate.py < /dev/null      # expect: BLOCK on the stranded deliverable
rm -rf work/_gatetest
```
