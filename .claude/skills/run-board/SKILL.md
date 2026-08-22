---
name: run-board
description: >
  The run board — the numbered vertical roster of every agent in a hunt, its status, and the running
  tally, re-emitted at every step boundary so the user can always see what is running and what is
  still queued. One source of truth for how progress is displayed. Load at the start of every hunt
  (the orchestrator owns the board; every agent writes lines that reference it).
---

# The run board

A hunt is a fleet of agents, and the user cannot see any of them. The board is the fix: **one numbered
vertical list of every agent in the run, printed in full at every boundary**, with a status marker and
a one-line result per row. Not a paragraph about what is happening — a board you re-print.

Rule: **no boundary passes without a board.** Entering a step, tasking an agent, booting the target,
starting a sweep, an agent returning, a confirmation, a gate — reprint the board. If you are about to
go quiet for more than a couple of minutes, print it first.

## The board is state, not prose — drive it with `hunt board`

Do not retype the board from memory. It lives in `work/<slug>/board.json` and `hunt board` renders
it, so a reprint physically cannot disagree with what happened. Open it with the **whole roster** at
the start of the hunt, then mutate one row at a time:

```
hunt board init <target> --kind src --step 1/9 \
     --row "web-recon-hunter:surface inventory" \
     --row "injection-hunter:B injection & exec" \
     --row "authz-logic-hunter:A access control" ...

hunt board start  <target> 2 --result "tracing 6 ranked leads"
hunt board set    <target> 2 --result "7/11 classes · 1 HIT (SSTI /render)" --show
hunt board done   <target> 2 --result "1 HIT · 9 CLEAR · 1 BLOCKED"
hunt board block  <target> 5 --result "no browser — install playwright to unblock"
hunt board tally  <target> --step 5/9 --covered 23/47 --hit 3 --clear 18 --blocked 2
hunt board lane   <target> <id> --layout github     # appends writer/auditor/editor/gate rows
hunt board show   <target>                          # reprint — this is what you paste
```

Every mutating call reprints the full board, so the reprint at a boundary is free: the call that
records the state *is* the call that prints it. Row numbers are assigned at `init` and never reused;
`add` and `lane` append. The tally is forward-only — a call that would lower `covered`/HIT/CLEAR/
BLOCKED is refused rather than silently accepted, because a tally that can go down is a tally that
was guessed at. Elapsed clocks per row come from the state, not from your sense of how long it felt.

`hunt board show <target> --watch` redraws every 2s — hand that to the user in a second terminal and
they can watch the fleet without reading the transcript.

The roster itself is queryable: **`hunt agents`** prints every agent with its model, tools and the
skills it loads, and `hunt agents --skills` inverts it (each skill, and which agents load it). Read
it when planning the roster so the rows you open match agents that actually exist.

## The format

`hunt board show` emits exactly this. The format is documented here because you still need to read a
board — but you produce it with the command, never by hand.

```
HUNT BOARD — acme/example-app (src) · step 5/9 · covered 23/47 · 3 HIT · 18 CLEAR · 2 BLOCKED
  1. [x] web-recon-hunter     surface inventory     done     61 endpoints · 118 params · 3 identities
  2. [>] injection-hunter     B injection & exec    RUNNING  7/11 classes · 1 HIT (SSTI /render)
  3. [>] authz-logic-hunter   A access control      RUNNING  12/13 classes · 0 HIT
  4. [x] authn-crypto-hunter  C identity & secrets  done     0 HIT · 9 CLEAR · 1 BLOCKED
  5. [ ] client-side-hunter   D client-side         queued   browser required
  6. [ ] report-writer        EX-01 · github        queued
  7. [ ] report-auditor       EX-01 · factual       queued
  8. [ ] report-editor        EX-01 · editorial     queued
  9. [ ] delivery gate        EX-01 · receipt       queued
```

**Header line:** target + kind · `step <n>/<N>` · the coverage tally (`covered X/Y · n HIT · n CLEAR ·
n BLOCKED`). The tally is cumulative and only ever moves forward; the final coverage table is this
tally expanded.

**Rows:** `<n>. <status> <agent>  <scope>  <state>  <one-line result>`.

- Numbers are **stable for the whole hunt**. Row 3 is the same agent in every reprint. New work appends
  new rows; nothing is renumbered, ever — the user is tracking numbers between prints.
- **Every agent appears from the first print**, including ones not started yet. A roster that grows as
  you go hides how much is left. Print the plan, then watch it fill in.
- The result column is facts, not adjectives: counts, verdicts, the endpoint that fired.

**Status markers:**

| Marker | Meaning |
|---|---|
| `[ ]` | queued — planned, not started |
| `[>]` | running now |
| `[x]` | returned, work accepted |
| `[!]` | blocked — say what blocked it in the result column, and what would unblock it |
| `[-]` | not applicable — say why (`N/A black-box`, `no browser`) |

`[!]` and `[-]` are first-class outcomes. A row quietly flipped to `[x]` because it was inconvenient to
explain is the one failure mode this board exists to prevent.

## Per-agent lines reference the board

Every agent's own progress lines carry its board number, so any line traces to a row:

```
[2/9 injection] tracing 6 ranked leads + 3 unflagged handlers
[2/9 injection] SSTI HIT on /render?tpl — marker 49 in body, reproduced 3×
[2/9 injection] 7/11 classes done · 1 HIT · 5 CLEAR · 1 BLOCKED
```

Hunter subagents do not print the board (they cannot see the other rows). They print their own numbered
lines; the orchestrator folds those into the next reprint.

## Whoever is running the hunt owns the board

`sec-orchestrator` is usually itself a subagent, spawned by the main session. That hands off board
ownership, and getting this wrong is how a board gets printed once and never again:

- The **main session** prints the opening board when it delegates, and gives the `Agent` call a
  description that says what is starting — `"Hunt langchain: recon + scan"`, not `"Security hunt"`.
- From the moment it starts, **the orchestrator owns the board** and reprints it. Everything the user
  sees for the next hour is the orchestrator's output, so a board it doesn't print is a board that
  doesn't exist. Print one immediately on starting, before the first tool call.
- When the orchestrator returns, the main session prints the final board.

**Two counters, don't conflate them.** `step <n>/<N>` is the workflow step (`sec-orchestrator`
§ Workflow, 0–8). The row numbers are agents. A board can legitimately read `step 3/9` with 8 rows —
they count different things, so label them and never renumber rows to match the step count.

## Every action has to be legible

A board tells the user *which* agent is working. It doesn't tell them what that agent is doing right
now, and a column of raw shell is not an answer:

```
Bash(cd "C:/.../libs/langchain_v1/langchain" && sed -n '100,200p' chat_models/base.py)
Running…
```

That is the hunt's visible surface for minutes at a time, and it reads as noise. **Every tool call
carries a `description` written for the user, not for you** — say what it does and why it matters, in
active voice:

| Instead of | Write |
|---|---|
| `Security hunt on langchain` | `Hunt langchain: recon + static scan` |
| the raw `sed -n '100,200p' chat_models/base.py` | `Read the model-init path for an unvalidated provider string` |
| `tail -30 scan.log && ls work/langchain/` | `Check whether the static scan finished and what it produced` |
| `python -m venv lcvenv && pip install …` | `Build the throwaway venv the PoC will run in` |

Rules that make this hold up:

- **Name the intent, not the mechanics.** `cd`, `tail`, pipes and flags are visible in the command
  already. The description is the part the command cannot say: what you expect to learn.
- **Announce anything slow before you start it** — a dependency install, a clone, a boot, a fuzz pass,
  a crawl. `[2/9 injection] installing langchain into a throwaway venv, ~2 min` costs one line and
  removes the entire "is it stuck?" question.
- **A long silent stretch needs a board reprint, not just a description.** If several tool calls run
  back to back, reprint between them with the row's result column updated.
- **Say what came back.** A tool call whose result never gets mentioned reads as work that vanished.
  One line: what you read, and what it changed about the hypothesis.

## The report lane

The moment a lead is confirmed, the hunt opens a **report lane** for it and the lane's agents are
appended to the board as their own rows — writer, auditor, editor, gate — tagged with the finding id.
Confirming a bug and leaving no visible trace of what happens to it next is exactly the gap this
closes. See the report-first rule in `sec-orchestrator` and `report-craft`.

```
HUNT BOARD — acme/example-app (src) · step 6/12 · covered 31/47 · 1 CONFIRMED (EX-01) · 2 leads
  ...
  6. [x] report-writer        EX-01 · github    done     reports/acme__example-app-CWE-400-EX-01.md
  7. [x] report-auditor       EX-01 · factual   PASS     18/18 file:line verified at 6b0c9c1
  8. [>] report-editor        EX-01 · editorial RUNNING
  9. [ ] delivery gate        EX-01 · receipt   queued
 10. [ ] injection-hunter     B — resume        queued   3 classes left after EX-01 ships
```

A second finding opens a second lane with its own rows (11, 12, 13, 14), never by reusing the first
lane's numbers.

## Mirror it in TodoWrite

Keep the same rows in TodoWrite so the state is visible in the UI as well as in the text. Same numbers,
same order. The board is the narration; the todo list is the checkbox.

## What not to do

- Do not print a partial board ("the two agents that changed"). Reprint all of it — the value is that
  one glance answers *what is left*.
- Do not renumber, reorder, or drop finished rows.
- Do not print a board with an invented row state. A row is `[x]` when the agent returned and you read
  what it returned, not when you expect it to finish soon (No Assumption, `guardrails`). `hunt board
  done` is the only thing that sets `[x]` — call it *after* reading the return, never before.
- Do not hand-type a board block. If you find yourself typing `HUNT BOARD —` into a message, the state
  and the print have already diverged; run `hunt board show` instead.
- Do not replace the board with prose. Prose goes *after* it, when something needs explaining.
