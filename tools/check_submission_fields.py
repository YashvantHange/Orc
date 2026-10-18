#!/usr/bin/env python3
"""
check_submission_fields.py - the submission-fields contract, machine-checked.

Why this exists. On 2026-09-09 a single report's submission-fields/ folder was rebuilt FIVE times in
one session - 7 files, then 3, then 5, then 15, then 9-plus-a-README - because the required shape was
being re-derived from memory and from whichever precedent folder happened to be looked at first. Every
rebuild cost tokens and produced a different answer. The shape was never in doubt; it was simply never
written down anywhere a machine could check it.

What is actually KNOWN about the Google Bug Hunters form, from the report packets that were really
submitted (see reports/GCLI-058-ZIPSLIP-*/HOW-TO-FILE.md): only TWO fields are OBSERVED - the "Select
vulnerability type" dropdown, and a Description field with a 200-character HARD limit. Every other
field name in every packet here is ASSUMED from ordinary report structure, because the form is a
login-gated single-page app that cannot be fetched.

So this check does NOT enforce a fixed file list - doing that was itself a mistake, and it would have
rejected the six-field layout Google actually received. It enforces only what is known:

    * the two observed fields must be present and within their observed limits
    * no field file may be a copy of the report body (the receipt binds the report's sha256; a
      duplicate drifts out of sync silently, which has already happened)
    * no field file may contain instructions instead of a value
    * an availability-only finding must have no packet at all

AND: the presence of this folder MEANS "this is going to g.co/vulnz". So it is also checked against
the one scope rule that has actually cost money here. Google OSS VRP defines a qualifying product
vulnerability as one "substantially affecting the confidentiality or integrity of user data".
Availability is absent from that definition. SHAKA-006 was runtime-proven, twice-audited, receipted,
filed - and closed "out of scope for the selected VRP" - because its vector was C:N/I:N/A:H. An
availability-only finding must NOT have a submission packet at all; its ceiling is an upstream issue.

Run it directly, or from the Stop hook:  python tools/check_submission_fields.py
Exit 0 = clean. Exit 1 = problems printed to stdout, one per line.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# The only two fields OBSERVED on the real form. Matched by suffix so the numbering can vary.
REQUIRED_SUFFIXES = ("-vulnerability-type.txt", "-description.txt")

# A field file is a paste-ready VALUE. Guidance belongs in HOW-TO-FILE.md, not here.
INSTRUCTION_MARKERS = ("tick the box", "paste this", "paste into", "select the", "dropdown",
                       "must be selected", "do not paste", "see how-to-file", "-> the ")

# Google Bug Hunters truncates the description field at 200 characters.
DESCRIPTION_LIMIT = 200


def problems() -> list:
    out = []
    rdir = ROOT / "reports"
    if not rdir.is_dir():
        return out
    for folder in sorted(p for p in rdir.iterdir() if p.is_dir()):
        name = folder.name
        # A finding folder is one with a report .md that is not the routing companion.
        if not any(m.name != "HOW-TO-FILE.md" for m in folder.glob("*.md")):
            continue
        # Only folders that have been routed for delivery owe submission fields. A folder with no
        # HOW-TO-FILE.md has not been routed yet, and nagging about it teaches people to ignore this.
        if not (folder / "HOW-TO-FILE.md").exists():
            continue
        # A waived finding is one explicitly not being delivered (withdrawn, out of scope). It owes
        # no packet, and nagging about it would teach people to ignore this check.
        gdir = ROOT / "state" / "gate"
        waived = gdir.is_dir() and any(w.name.endswith(".waived.json") and
                                       name.startswith(w.name[:-len(".waived.json")] + "-")
                                       for w in gdir.iterdir())

        # Does this finding belong at a VRP at all? The vector is the authority. Prefer the ledger
        # (a GitHub-issue report body carries no CVSS line, so the report alone is not enough), then
        # fall back to the report. If a packet exists and the vector cannot be established, BLOCK:
        # this check fails CLOSED, because the failure it exists to prevent is an out-of-scope
        # submission going out looking finished.
        body = folder / f"{name}.md"
        vec = ""
        try:
            led = json.loads((ROOT / "state" / "ledger.json").read_text(encoding="utf-8"))
            for rec in led.get("findings", []):
                rp = str(rec.get("report_path") or "").replace("\\", "/")
                if rp and rp.split("/")[1:2] == [name]:
                    vec = str(rec.get("cvss") or "")
                    break
        except (OSError, json.JSONDecodeError, IndexError):
            pass
        if not vec and body.exists():
            m = re.search(r"CVSS:3\.1/[A-Z:/]+", body.read_text(encoding="utf-8", errors="replace"))
            vec = m.group(0) if m else ""
        vec = vec.replace(" ", "")
        availability_only = bool(vec) and "C:N" in vec and "I:N" in vec and "A:N" not in vec

        sf = folder / "submission-fields"
        if sf.is_dir() and not vec:
            out.append(f"reports/{name}: has submission-fields/ but no CVSS vector can be found in "
                       f"the ledger or the report. Scope cannot be checked, so this fails closed. "
                       f"Record the vector with `hunt ledger update --id <ID> --set cvss='...'`")
            continue
        if availability_only:
            if sf.is_dir():
                out.append(f"reports/{name}: has submission-fields/ but its vector is "
                           f"availability-only ({vec}). That packet means \"going to g.co/vulnz\", "
                           f"and Google OSS VRP requires confidentiality or integrity impact - "
                           f"SHAKA-006 was closed out-of-scope on exactly this. Delete the packet and "
                           f"route to an upstream GitHub issue")
            continue
        if not sf.is_dir():
            if (folder / "submission").is_dir():
                continue
            if not vec or waived:
                continue
            out.append(f"reports/{name}: no submission-fields/ (vector {vec} is in scope for a VRP)")
            continue

        present = sorted(p.name for p in sf.iterdir() if p.is_file())
        for suffix in REQUIRED_SUFFIXES:
            if not any(n.endswith(suffix) for n in present):
                out.append(f"reports/{name}: no *{suffix} in submission-fields/. That field is "
                           f"OBSERVED on the real form and must be filled")

        body = folder / f"{name}.md"
        for fname in present:
            f = sf / fname
            text = f.read_text(encoding="utf-8", errors="replace")
            if not text.strip():
                out.append(f"reports/{name}: submission-fields/{fname} is empty")
                continue
            low = text.lower()
            for marker in INSTRUCTION_MARKERS:
                if marker in low:
                    out.append(f"reports/{name}: submission-fields/{fname} contains instruction text "
                               f"(\"{marker}\"). A field file holds a paste-ready value only")
                    break
            # The scope rule, enforced where it is cheapest to catch: before the packet is built.
            if fname.endswith("-severity.txt"):
                v = text.replace(" ", "")
                if "C:N" in v and "I:N" in v and "A:N" not in v:
                    out.append(
                        f"reports/{name}: 04-severity.txt is availability-only ({text.strip()}). "
                        f"Google OSS VRP requires a finding \"substantially affecting the "
                        f"confidentiality or integrity of user data\"; availability is not in that "
                        f"definition, and a sibling finding was closed out-of-scope on exactly this. "
                        f"Delete submission-fields/ entirely - this belongs in an upstream GitHub "
                        f"issue, not a VRP submission")
            if fname.endswith("-description.txt") and len(text) > DESCRIPTION_LIMIT:
                out.append(f"reports/{name}: submission-fields/{fname} is {len(text)} chars, over "
                           f"the {DESCRIPTION_LIMIT}-char hard limit observed on the form")
            # A field file may legitimately be long - the submitted GCLI-058 packet has a
            # 6153-char technical-details field. What it may NOT be is a COPY of the report body,
            # because the receipt binds the report's sha256 and a duplicate drifts out of sync
            # silently. So test for duplication, not for length.
            if body.exists() and len(text) > 500:
                btext = body.read_text(encoding="utf-8", errors="replace")
                # Compare a substantive slice, not the first few lines: a report can open
                # with a short table header that would fall under any length threshold.
                probe = text.strip()[:300]
                if len(probe) > 120 and probe in btext:
                    out.append(f"reports/{name}: submission-fields/{fname} reproduces the opening of "
                               f"the report body verbatim. Paste from the report itself; a copy here "
                               f"drifts out of sync with the receipted sha256")
    return out


def main() -> int:
    probs = problems()
    if not probs:
        print("submission-fields: OK")
        return 0
    for p in probs:
        print(p)
    return 1


if __name__ == "__main__":
    sys.exit(main())
