#!/usr/bin/env python3
"""
board.py — the run board as STATE, not as prose an agent retypes from memory.

The `run-board` skill says: one numbered roster of every agent in the hunt, reprinted in full at
every boundary, never renumbered, never guessed at. Retyping that by hand is how rows drift, how
a `[>]` stays `[>]` after the agent returned, and how the board silently stops being printed.

So the board lives in work/<slug>/board.json. Agents mutate one row at a time:

    hunt board init <target> --step 1/9 --row "web-recon-hunter:surface inventory" --row ...
    hunt board start 2                       -> [>] and the row's clock starts
    hunt board set 2 --result "7/11 classes - 1 HIT (SSTI /render)"
    hunt board done 2 --result "1 HIT - 9 CLEAR - 1 BLOCKED"
    hunt board block 5 --result "no browser - install playwright to unblock"
    hunt board tally --covered 23/47 --hit 3 --clear 18 --blocked 2 --step 5/9
    hunt board lane <id> --layout github     -> appends the 4 report-lane rows
    hunt board show                          -> render (this is what gets pasted)
    hunt board show --watch                  -> live redraw in a second terminal

Rendering is derived: statuses, elapsed clocks and the tally can't disagree with the state because
there is only one copy of them. Row numbers are assigned once at init and never reused.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

STATUSES = {
    "queued":  ("[ ]", "queued",  "dim"),
    "running": ("[>]", "RUNNING", "cyan"),
    "done":    ("[x]", "done",    "green"),
    "blocked": ("[!]", "BLOCKED", "yellow"),
    "na":      ("[-]", "N/A",     "dim"),
}

_C = {"dim": "\033[2m", "cyan": "\033[36m", "green": "\033[32m", "yellow": "\033[33m",
      "red": "\033[31m", "bold": "\033[1m", "off": "\033[0m"}


def _color_on() -> bool:
    if os.environ.get("NO_COLOR") or os.environ.get("HUNT_BOARD_PLAIN"):
        return False
    if not sys.stdout.isatty():
        return False
    if os.name == "nt":                       # modern terminals need VT explicitly enabled
        try:
            import ctypes
            k = ctypes.windll.kernel32
            k.SetConsoleMode(k.GetStdHandle(-11), 7)
        except Exception:                     # noqa: BLE001 - cosmetic only
            return False
    return True


def _c(text: str, name: str, on: bool) -> str:
    return f"{_C[name]}{text}{_C['off']}" if on and name in _C else text


def _unicode_ok() -> bool:
    """A cp1252 console turns '·' into a replacement blob — check before betting the layout on it."""
    try:
        "· — ".encode(sys.stdout.encoding or "ascii")
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def _sep(text: str) -> str:
    return text if _unicode_ok() else text.replace("·", "|").replace("—", "-")


# --------------------------------------------------------------------------- state ---
def board_path(target: str) -> Path:
    sys.path.insert(0, str(ROOT / "static"))
    import _common as C
    return C.workdir(target) / "board.json"


def load(target: str) -> dict:
    p = board_path(target)
    if not p.exists():
        raise SystemExit(f"no board for {target!r} — run `hunt board init {target} --row ...` first")
    return json.loads(p.read_text(encoding="utf-8"))


def save(target: str, doc: dict) -> Path:
    doc["updated"] = time.time()
    p = board_path(target)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return p


def _row(doc: dict, n: int) -> dict:
    for r in doc["rows"]:
        if r["n"] == n:
            return r
    raise SystemExit(f"no row {n} on the board (rows: {', '.join(str(r['n']) for r in doc['rows'])})")


def _parse_step(s: str) -> list[int]:
    m = re.fullmatch(r"\s*(\d+)\s*/\s*(\d+)\s*", s or "")
    if not m:
        raise SystemExit(f"--step wants N/M, got {s!r}")
    return [int(m.group(1)), int(m.group(2))]


def _add_rows(doc: dict, specs: list[str]) -> list[dict]:
    """A spec is 'agent:scope' — scope optional. Numbers continue from the highest in use."""
    nxt = max((r["n"] for r in doc["rows"]), default=0) + 1
    added = []
    for spec in specs:
        agent, _, scope = spec.partition(":")
        row = {"n": nxt, "agent": agent.strip(), "scope": scope.strip(), "status": "queued",
               "result": "", "started": None, "ended": None}
        doc["rows"].append(row)
        added.append(row)
        nxt += 1
    return added


# ------------------------------------------------------------------------ commands ---
def cmd_init(a) -> int:
    doc = {"target": a.target, "kind": a.kind, "step": _parse_step(a.step or "1/9"),
           "tally": {"covered": [0, 0], "HIT": 0, "CLEAR": 0, "BLOCKED": 0, "CONFIRMED": []},
           "started": time.time(), "updated": time.time(), "rows": []}
    if not a.row:
        raise SystemExit("init needs the WHOLE roster up front (--row agent:scope, repeatable) — "
                         "a roster that grows as you go hides how much is left (run-board skill)")
    _add_rows(doc, a.row)
    save(a.target, doc)
    return _render(doc)


def cmd_add(a) -> int:
    doc = load(a.target)
    added = _add_rows(doc, a.row)
    save(a.target, doc)
    print(f"appended rows {', '.join(str(r['n']) for r in added)}")
    return _render(doc)


def cmd_status(a, status: str) -> int:
    doc = load(a.target)
    row = _row(doc, a.n)
    row["status"] = status
    if status == "running" and not row["started"]:
        row["started"] = time.time()
    if status in ("done", "blocked", "na"):
        row["ended"] = time.time()
    if getattr(a, "result", None):
        row["result"] = a.result
    if getattr(a, "scope", None):
        row["scope"] = a.scope
    save(a.target, doc)
    return _render(doc)


def cmd_set(a) -> int:
    doc = load(a.target)
    row = _row(doc, a.n)
    if a.result:
        row["result"] = a.result
    if a.scope:
        row["scope"] = a.scope
    if a.status:
        return cmd_status(a, a.status)
    save(a.target, doc)
    return _render(doc) if a.show else 0


def cmd_tally(a) -> int:
    doc = load(a.target)
    t = doc["tally"]
    if a.covered:
        m = re.fullmatch(r"\s*(\d+)\s*/\s*(\d+)\s*", a.covered)
        if not m:
            raise SystemExit(f"--covered wants N/M, got {a.covered!r}")
        new = [int(m.group(1)), int(m.group(2))]
        if new[0] < t["covered"][0]:
            raise SystemExit(f"coverage only moves forward: {t['covered'][0]} -> {new[0]} refused")
        t["covered"] = new
    for key, val in (("HIT", a.hit), ("CLEAR", a.clear), ("BLOCKED", a.blocked)):
        if val is not None:
            if val < t[key]:
                raise SystemExit(f"{key} only moves forward: {t[key]} -> {val} refused")
            t[key] = val
    if a.confirmed:
        for fid in a.confirmed:
            if fid not in t["CONFIRMED"]:
                t["CONFIRMED"].append(fid)
    if a.step:
        doc["step"] = _parse_step(a.step)
    save(a.target, doc)
    return _render(doc)


def cmd_lane(a) -> int:
    """A confirmed lead opens its own report lane — writer, auditor, editor, gate — as new rows."""
    doc = load(a.target)
    fid, layout = a.id, a.layout
    added = _add_rows(doc, [
        f"report-writer:{fid} · {layout}",
        f"report-auditor:{fid} · factual",
        f"report-editor:{fid} · editorial",
        f"delivery gate:{fid} · receipt",
    ])
    if fid not in doc["tally"]["CONFIRMED"]:
        doc["tally"]["CONFIRMED"].append(fid)
    save(a.target, doc)
    print(f"report lane for {fid} -> rows {added[0]['n']}–{added[-1]['n']}")
    return _render(doc)


def cmd_show(a) -> int:
    if not a.watch:
        return _render(load(a.target))
    try:
        while True:
            doc = load(a.target)
            sys.stdout.write("\033[2J\033[H")
            _render(doc)
            live = [r for r in doc["rows"] if r["status"] == "running"]
            if not live and all(r["status"] != "queued" for r in doc["rows"]):
                print("\n(no rows running and none queued — board is final)")
                return 0
            time.sleep(a.interval)
    except KeyboardInterrupt:
        return 0


# ------------------------------------------------------------------------ renderer ---
def _elapsed(row: dict) -> str:
    if not row["started"]:
        return ""
    end = row["ended"] or time.time()
    s = int(end - row["started"])
    return f"{s}s" if s < 90 else f"{s // 60}m{s % 60:02d}"


def _header(doc: dict) -> str:
    t = doc["tally"]
    bits = [f"{doc['target']} ({doc['kind']})",
            f"step {doc['step'][0]}/{doc['step'][1]}",
            f"covered {t['covered'][0]}/{t['covered'][1]}",
            f"{t['HIT']} HIT", f"{t['CLEAR']} CLEAR", f"{t['BLOCKED']} BLOCKED"]
    if t["CONFIRMED"]:
        bits.append(f"CONFIRMED {', '.join(t['CONFIRMED'])}")
    return _sep("HUNT BOARD — " + " · ".join(bits))


def _render(doc: dict) -> int:
    on = _color_on()
    rows = sorted(doc["rows"], key=lambda r: r["n"])
    w_agent = max((len(r["agent"]) for r in rows), default=10)
    w_scope = max((len(r["scope"]) for r in rows), default=10)
    w_state = max(len(STATUSES[r["status"]][1]) for r in rows) if rows else 7

    print("```")
    print(_c(_header(doc), "bold", on))
    for r in rows:
        mark, state, col = STATUSES[r["status"]]
        el = _elapsed(r)
        line = _sep(f"{r['n']:>3}. {mark} {r['agent']:<{w_agent}}  {r['scope']:<{w_scope}}  "
                    f"{state:<{w_state}}  {r['result']}")
        if el:
            line += _c(f"   ({el})", "dim", on)
        print(_c(line, col, on) if col in ("cyan", "green", "yellow") else line)
    total = int(time.time() - doc["started"])
    print(_c(_sep(f"     elapsed {total // 60}m{total % 60:02d} · "
                  f"{sum(1 for r in rows if r['status'] == 'done')}/{len(rows)} rows returned"),
             "dim", on))
    print("```")
    return 0


# ------------------------------------------------------------- agent/skill roster ---
def _frontmatter(p: Path) -> dict:
    txt = p.read_text(encoding="utf-8", errors="replace")
    if not txt.startswith("---"):
        return {}
    end = txt.find("\n---", 3)
    if end < 0:
        return {}
    block, out, key = txt[3:end], {}, None
    for line in block.splitlines():
        m = re.match(r"^(\w[\w-]*):\s*(.*)$", line)
        if m:
            key = m.group(1)
            out[key] = m.group(2).strip().lstrip(">").strip()
        elif key and line.strip():
            out[key] = (out[key] + " " + line.strip()).strip()
    return out


def cmd_agents(a) -> int:
    """The roster: every agent, the model it runs on, its tools, and the skills it loads."""
    on = _color_on()
    adir, sdir = ROOT / ".claude" / "agents", ROOT / ".claude" / "skills"
    skills = {d.name: _frontmatter(d / "SKILL.md").get("description", "")
              for d in sorted(sdir.iterdir()) if (d / "SKILL.md").exists()}

    if a.skills:
        print(_c(f"SKILLS ({len(skills)})", "bold", on))
        for name, desc in skills.items():
            users = [f.stem for f in sorted(adir.glob("*.md"))
                     if re.search(rf"`{re.escape(name)}`", f.read_text(encoding="utf-8"))]
            print(f"\n  {_c(name, 'cyan', on)}   {_c('loaded by: ' + (', '.join(users) or '—'), 'dim', on)}")
            print(f"    {_squash(desc, a.width)}")
        return 0

    files = sorted(adir.glob("*.md"))
    print(_c(f"AGENT ROSTER ({len(files)} agents · {len(skills)} skills)", "bold", on))
    for f in files:
        fm = _frontmatter(f)
        txt = f.read_text(encoding="utf-8")
        loads = [s for s in skills if re.search(rf"`{re.escape(s)}`", txt)]
        print(f"\n  {_c(fm.get('name', f.stem), 'cyan', on)}"
              f"  {_c('model=' + fm.get('model', '?'), 'dim', on)}")
        print(f"    {_squash(fm.get('description', ''), a.width)}")
        print(f"    {_c('tools ', 'dim', on)}{fm.get('tools', '—')}")
        print(f"    {_c('skills', 'dim', on)} {', '.join(loads) or '—'}")
    print(f"\n{_c('  every hunt row on the board maps to one of these agents.', 'dim', on)}")
    return 0


def _squash(text: str, width: int) -> str:
    words, lines, cur = text.split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    lines.append(cur)
    return ("\n    ".join(lines)).rstrip()
