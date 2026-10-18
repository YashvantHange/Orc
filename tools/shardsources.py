#!/usr/bin/env python3
"""
shardsources.py - where each swarm role gets its shards.

One target, three hunting METHODS, three tables already written down:

    coverage -> vuln-playbooks  "Required coverage - the matrix"   (via audit_coverage)
    depth    -> deep-trace      §3 "Indirection catalog"           (12 patterns)
    stack    -> stack-playbooks nine per-stack surface tables

Every one of them is parsed out of the skill that already documents it, never copied into Python.
A second copy would drift, and the copy is what a hunter would then be graded against.

WHY THE OWNER MAPS ARE HAND-WRITTEN TABLES. tools/audit_coverage.py records what happened the last
time this was done by similarity scoring: it called `idor_enum` missing because the row says
"Authorization flaws (IDOR/BOLA)", and called "MCP-surface auth" covered because `missing_auth` also
contains "auth" - wrong in both directions at every threshold tried. A shard assignment resting on
string similarity is the "plausible but unverified" thing `guardrails` forbids, so the maps below are
explicit and each entry is checkable by opening the row it names. A label that is not in the table is
a hard error, never a default owner: silently handing a shard to the wrong specialist produces a
confident CLEAR from an agent that was never looking at its own class.

The stack owners are taken from the coverage matrix's own owner column wherever a corresponding row
exists, so the two tables cannot disagree about who owns SSRF. That is also why the matrix row
"Stack-specific surface (framework/platform)" carries the owner `(per row hit)` - the matrix
deliberately defers stack surfaces to whatever class the surface actually hits, which is this file.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILLS = ROOT / ".claude" / "skills"
DEEP_TRACE = SKILLS / "deep-trace" / "SKILL.md"
STACK_PLAYBOOKS = SKILLS / "stack-playbooks" / "SKILL.md"

sys.path.insert(0, str(ROOT / "tools"))


class ShardSourceError(Exception):
    """A skill table did not parse, or named something with no owner. Always fatal."""


# ---------------------------------------------------------------------------- coverage ---
def matrix_rows(kind: str | None = None) -> list:
    """(section, class, playbook, kind, owner) - re-exported so callers have one import."""
    import audit_coverage as A
    rows = A.matrix_rows()
    if kind:
        want = {"src": {"src", "both"}, "url": {"url", "both"},
                "grey": {"src", "url", "both"}}[kind]
        rows = [r for r in rows if r[3] in want]
    return sorted(rows, key=lambda r: (r[0], r[1]))


# ------------------------------------------------------------------------------- depth ---
# Indirection pattern -> the hunter that owns what it usually hides. Taken from the catalog's own
# "Usually hides" column, one line per pattern, in the order the catalog lists them.
DEPTH_OWNERS = {
    "Base class + override":        "server-side-hunter",   # traversal, upload validation
    "Registry / plugin table":      "rce-exec-hunter",      # any sink, reached by a body string
    "Decorator factory":            "authz-logic-hunter",   # the wrapper checks the wrong thing
    "DI container / provider":      "authz-logic-hunter",   # principal replaced by a service id
    "Generic CRUD factory":         "authz-logic-hunter",   # missing per-object authz, every model
    "Middleware chain":             "authn-crypto-hunter",  # auth bypass by prefix/method mismatch
    "Job queue / worker":           "authz-logic-hunter",   # principal dropped at the boundary
    "Event bus / signal / hook":    "authz-logic-hunter",   # writes that skip the API's checks
    '"Safe" wrapper util':          "server-side-hunter",   # the one call site that doesn't use it
    "Config-named handler":         "rce-exec-hunter",      # unreviewed code paths
    "Dynamic import / reflection":  "rce-exec-hunter",      # RCE, unroutable-looking routes
    "Cross-language / RPC / MCP":   "authz-logic-hunter",   # guard on one side only
}


def _table_rows(text: str, start: str, end: str | None) -> list:
    """Data rows of the first markdown table between two headings, split on '|'.

    The separator line starts '|-' rather than '| ', so requiring the space drops it without a
    second pattern. The header row is dropped by the caller, which knows its first cell.
    """
    body = text.split(start, 1)[1] if start in text else ""
    if not body:
        raise ShardSourceError(f"heading {start!r} not found")
    if end and end in body:
        body = body.split(end, 1)[0]
    out = []
    for line in body.splitlines():
        if not line.startswith("| "):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        out.append(cells)
    return out


def indirection_rows() -> list:
    """The 12 places a sink hides: [{pattern, looks_like, resolve_by, hides, owner}]."""
    text = DEEP_TRACE.read_text(encoding="utf-8")
    rows = _table_rows(text, "## 3. Indirection catalog", "## 4.")
    out = []
    for cells in rows:
        if len(cells) < 4 or cells[0] == "Pattern":
            continue
        pattern = cells[0]
        owner = DEPTH_OWNERS.get(pattern)
        if owner is None:
            raise ShardSourceError(
                f"deep-trace lists the indirection pattern {pattern!r}, which DEPTH_OWNERS does not "
                f"map to a hunter. Add it deliberately - a defaulted owner hands the shard to an "
                f"agent that is not looking at that class and gets a confident CLEAR back.")
        out.append({"pattern": pattern, "looks_like": cells[1], "resolve_by": cells[2],
                    "hides": cells[3], "owner": owner})
    if len(out) != 12:
        raise ShardSourceError(
            f"deep-trace §3 says 'the 12 places a sink hides' but {len(out)} parsed. The heading and "
            f"the table disagree; fix the skill rather than loosening this check.")
    return out


# ------------------------------------------------------------------------------- stack ---
# Stack-table "Matrix row" label -> owner. Taken from the coverage matrix's owner column wherever a
# corresponding row exists, so the two tables cannot disagree about who owns a class.
STACK_OWNERS = {
    ("A", "Auth bypass"):                 "authn-crypto-hunter",
    ("A", "BFLA"):                        "authz-logic-hunter",
    ("A", "IDOR"):                        "authz-logic-hunter",
    ("A", "Mass assignment"):             "authz-logic-hunter",
    ("A", "Priv-esc"):                    "authz-logic-hunter",
    ("A", "Trusted-header bypass"):       "authz-logic-hunter",
    ("B", "Code / expression injection"): "rce-exec-hunter",
    ("B", "Code injection"):              "rce-exec-hunter",
    ("B", "Command injection"):           "rce-exec-hunter",
    ("B", "Deserialization"):             "rce-exec-hunter",
    ("B", "Prototype pollution (server)"): "server-side-hunter",
    ("B", "RCE"):                         "rce-exec-hunter",
    ("B", "SQL injection / RCE"):         "datastore-hunter",
    ("B", "Template injection"):          "rce-exec-hunter",
    ("B", "Unsafe deserialization"):      "rce-exec-hunter",
    ("C", "Path traversal"):              "server-side-hunter",
    ("C", "SSRF"):                        "server-side-hunter",
    ("C", "Signed-URL abuse"):            "authz-logic-hunter",
    ("E", "Cache poisoning"):             "server-side-hunter",
    ("F", "Header/transport posture"):    "web-recon-hunter",
    ("F", "Info disclosure"):             "authn-crypto-hunter",
    ("F", "Secrets exposure"):            "authn-crypto-hunter",
    ("F", "Vulnerable components"):       "injection-hunter",
}

# A label naming two classes. The first owns the shard; the second is recorded as a handoff hint so
# the second half is not lost, which is what "one finding, two contributors" means in practice.
STACK_COMPOUND = {("A", "BFLA + F · Secrets"): ("authz-logic-hunter", "authn-crypto-hunter")}

# Surfaces that are deliberately not shards, with the reason - listed rather than silently skipped,
# exactly as audit_coverage.DELIBERATE does it.
STACK_NON_SHARDS = {
    "(recon)": "recon output, not a vulnerability class - web-recon-hunter already collects it",
    "out of scope on `url`": "would be an availability test on a live host; never fired",
}

_SECTION_SKIP = ("Step 0", "Step 0b", "Closing")


def _normalise_label(label: str) -> str:
    """Strip markdown emphasis and collapse whitespace.

    One real label is `E · Cache poisoning (**detection only**)`; the emphasis is presentation, and
    a lookup keyed on the raw string would miss it.
    """
    label = re.sub(r"\*\*(.*?)\*\*", r"\1", label)
    label = re.sub(r"\s*\((?:detection only|dev)\)\s*$", "", label, flags=re.I)
    return re.sub(r"\s+", " ", label).strip()


def _split_label(label: str) -> tuple[str, str] | None:
    """'C · SSRF' -> ('C', 'SSRF'). Returns None for anything not section-dot-label shaped."""
    m = re.match(r"^([A-G])\s*[·.]\s*(.+)$", label)
    return (m.group(1), m.group(2).strip()) if m else None


def stack_rows(stack: str | None = None) -> list:
    """Surfaces from stack-playbooks: [{stack, surface, note, label, owner, handoff}].

    The second column header differs between sections ("What to look for" in two, "Impact" in the
    other seven), so columns are taken by POSITION. Only the third column is relied on by name, and
    only to recognise and drop the header row.
    """
    text = STACK_PLAYBOOKS.read_text(encoding="utf-8")
    out, section = [], ""
    for line in text.splitlines():
        m = re.match(r"^## (.+?)\s*$", line)
        if m:
            section = m.group(1)
            continue
        if not section or any(section.startswith(s) for s in _SECTION_SKIP):
            continue
        if not line.startswith("| "):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 3 or cells[0] == "Surface":
            continue
        if stack and stack.lower() not in section.lower():
            continue

        raw = _normalise_label(cells[2])
        if raw in STACK_NON_SHARDS:
            continue
        parts = _split_label(raw)
        if parts is None:
            raise ShardSourceError(
                f"stack-playbooks section {section!r} labels a surface {cells[2]!r}, which is "
                f"neither 'X · Class' nor a listed non-shard. Add it to STACK_OWNERS or to "
                f"STACK_NON_SHARDS with a reason.")
        handoff = ""
        if parts in STACK_COMPOUND:
            owner, handoff = STACK_COMPOUND[parts]
        else:
            owner = STACK_OWNERS.get(parts)
        if not owner:
            raise ShardSourceError(
                f"stack-playbooks section {section!r} maps a surface to {raw!r}, which STACK_OWNERS "
                f"does not cover. Add it deliberately rather than defaulting - the wrong specialist "
                f"returns a confident CLEAR on a class it was never hunting.")
        out.append({"stack": section, "surface": cells[0], "note": cells[1],
                    "label": raw, "owner": owner, "handoff": handoff})
    if not out:
        raise ShardSourceError(
            f"no stack surfaces parsed{f' for {stack!r}' if stack else ''} - the table shape in "
            f"stack-playbooks changed, or the fingerprint names a stack the skill does not cover")
    return sorted(out, key=lambda r: (r["stack"], r["surface"]))


def stacks() -> list:
    """Every stack the playbook covers, in file order."""
    text = STACK_PLAYBOOKS.read_text(encoding="utf-8")
    names = [m.group(1).strip() for m in re.finditer(r"^## (.+?)\s*$", text, re.M)]
    return [n for n in names if not any(n.startswith(s) for s in _SECTION_SKIP)]
