# Harden the delivery gate: it cannot see a report edited through Bash

**Apply this by hand.** `tools/hooks/**` is write-protected from the agent, which is correct — an agent
must not be able to edit the machinery that constrains it. That protection is why this cannot be
self-applied.

Two files, one of them new, and no change to gate semantics.

## The hole

`.claude/settings.json` registers `on_report_write.py` as `PostToolUse` with `"matcher": "Write|Edit"`.
That hook is the **only** thing that calls `touch_report()`, and `pre_delivery_gate.py` (Stop) checks
exactly one set of files:

```python
reports = [r for r in touched_reports(d.get("session_id", "")) if is_report(str(ROOT / r))]
if not reports:
    return 0
```

So the gate's coverage is not "reports that changed" — it is "reports that changed *through the Write
or Edit tool*". A report rewritten with `sed -i`, a shell heredoc, or `python - <<'PY'` is invisible to
it, and the session ends clean.

Auto mode instructs the agent to prefer Bash for file edits. The invisible path is the default one.

## Observed 2026-09-22, in one session

Two reports in the same folder were modified:

| File | Written with | Recorded as touched | Gate saw it |
|---|---|---|---|
| `GITHUB-ISSUE.md` (new) | Write tool | yes | blocked, correctly |
| `HOW-TO-FILE.md` | `python - <<'PY'` through Bash | **no** | **nothing** |

`HOW-TO-FILE.md` was not an idle file. It carried a waiver bound to
`sha256:095d8233…`, and the edit moved it to `sha256:d87cf094…`, so `is_waived()` returned `False` —
the waiver had lapsed, exactly as its own `note` field says it should. Nothing fired. Verified:

```
$ python -c "... import _hookutil as H; print(H.is_waived('SHAKA-C8-001-HOWTO', live))"
False
$ python -c "... print(H.touched_reports('919c381c-...'))"
['reports/SHAKA-C8-001-shaka-player-clearkey-license-pin-bypass/GITHUB-ISSUE.md']
```

The gate blocked on one of the two changed reports and was never told about the other. Had the heredoc
that wrote `GITHUB-ISSUE.md` not failed on a quoting error — sending it to the Write tool instead —
the session would have ended with **both** edits unexamined and neither one mentioned.

## Fix — a drift hook that keys on bytes, not on which tool wrote them

### 1. New file: `tools/hooks/on_bash_report_change.py`

Copy `patches/on_bash_report_change.py` into `tools/hooks/`. It keeps a sha256 manifest of every
report and, after each Bash call, `touch_report()`s any whose bytes moved or that newly appeared. It
never blocks — the Stop gate stays the only thing that blocks; this just stops the gate being lied to
by omission.

### 2. `.claude/settings.json` — add a second `PostToolUse` entry

```json
    {
      "matcher": "Bash",
      "hooks": [
        {
          "type": "command",
          "command": "python \"$CLAUDE_PROJECT_DIR/tools/hooks/on_bash_report_change.py\"",
          "timeout": 30,
          "statusMessage": "checking reports for out-of-band changes"
        }
      ]
    }
```

Leave the existing `Write|Edit` entry alone. The two are complementary: `on_report_write.py` also does
the stale-audit warning, which this one deliberately does not duplicate.

## Verification, before and after installing

`patches/` has no `_hookutil` on its import path, so run the dry-run harness rather than the hook
directly. Expected results, all four observed on 2026-09-22 against 502 reports:

| Run | Expectation | Observed |
|---|---|---|
| seeding (no manifest) | flags nothing, writes 502 entries | flags nothing |
| steady state | flags nothing | flags nothing |
| report changed out of band | flagged | flagged |
| new report appears out of band | flagged | flagged |

The seeding run flagging nothing is a design choice, not a weakness. Drift needs a baseline, and a hook
whose first act is to block on a hundred files nobody touched this session gets switched off within the
day. Install it, let one Bash call seed the manifest, and it is armed from then on.

## What it also surfaces: 11 stale approvals already on disk

The seeding run writes `state/gate/stale_approvals.json` — reports whose receipt or waiver is bound to
a sha256 that no longer matches the file, i.e. an approval describing bytes that no longer exist. There
are **11** right now, inherited from earlier sessions:

```
reports/F001-GHSA-description.md
reports/F001-GHSA-submission.md
reports/F001-lightrag-webui-xss.md
reports/HKUDS__LightRAG-CWE-79-F001.md
reports/PrimeIntellect-ai__prime-agent-CWE-283-PA-001.md
reports/PrimeIntellect-ai__prime-agent-CWE-522-PA-002.md
reports/PrimeIntellect-ai__prime-agent-CWE-94-PA-005.md
reports/SHAKA-007-.../SHAKA-007-shaka-player-mp4-vtt-zero-length-box-hang.md
reports/SHAKA-C8-001-.../HOW-TO-FILE.md
reports/SHAKA-C9-001-.../HOW-TO-FILE.md
reports/fastify__fast-uri-CWE-436-FU-001.md
```

These are recorded, not blocked on: blocking every future session on a backlog it did not create is the
same mistake as blocking on the seeding run. Each needs either a re-run of `report-auditor` +
`report-editor` and `python hunt.py validate-report <ID>`, or a fresh waiver. Worth knowing how many of
those 11 were edited through Bash after their approval was issued — that is the same hole, before it
was named.

## Still unapplied from last time

`patches/HARDEN-delivery-gate-packaging.md` (2026-09-09) is **not applied** —
`grep -c DELIVERABLE_NAMES tools/hooks/pre_delivery_gate.py` returns `0`. Its finding #1 is the
sibling of this one: `is_report()` only matches paths under `reports/`, so a deliverable written to
`work/` is invisible to the whole gate the same way a Bash edit is. Two blind spots, both live, both
written up and waiting on a hand-apply. If these notes keep accumulating unapplied, the honest fix is
to grant write access to `tools/hooks/**` under review rather than to keep writing patches nobody
installs.
