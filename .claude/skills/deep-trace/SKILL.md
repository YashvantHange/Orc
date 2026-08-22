---
name: deep-trace
description: >
  Find the bugs that sit far from the route handler — behind dispatch tables, base classes and
  overrides, decorators, DI, plugin registries, job queues, and "safe" wrapper utils. Load when a
  surface read came up CLEAR, when a sink's argument arrives as a parameter rather than a request
  value, or when a guard lives in shared code. Includes the marker-driven runtime sink-instrumentation
  recipe that collapses any amount of indirection into one printed call stack.
---

# Deep trace — the bug is 3–6 hops from the handler

The shallow bug (`open(request.args["p"])` inside the handler) is found by every scanner and is usually
already an advisory. What's left in a mature target is **indirect**: the route delegates to a service,
the service dispatches through a registry, the registry hands you a subclass, the subclass calls a
shared helper, and the sink is in the helper's parent. Grep finds each piece; only a walk finds the bug.

**This procedure is entirely `Read` + `Grep` + your reasoning — no pipeline script is involved, and none
can do it.** SAST follows a fixed inter-procedural model and gives up exactly where these bugs live:
dynamic dispatch, string-keyed registries, subclass overrides, DI, config-named handlers, queue
boundaries, cross-language calls. **A scanner returning nothing is not evidence of absence** — for the
deep classes it is the expected result, so it may never be the basis for a `CLEAR`. The one runtime
technique here (§4) is a ten-line file *you* write and delete, not a tool you depend on; the static walk
alone is sufficient, and on a target that won't boot it's all you have.

**The rule this skill exists to enforce:** a `CLEAR` you reached by reading only the handler is not a
verdict, it's a glance. Every verdict is **depth-qualified** — say how far you actually walked:
> `CLEAR — upload type check in BaseUploader.validate:88; all 6 subclasses inherit it (enumerated, none
> override); sink reached at 3 hops.`
> `HIT — RawExporter.resolve:41 overrides the base's safe_join and joins directly; 4 hops from POST /export.`

## 1. Walk from both ends and meet in the middle

- **Bottom-up (default when you have a sink).** Sink → its callers → their callers → a route. A function
  has far fewer callers than a route has callees, so this converges fastest.
- **Top-down (default when you have an entrypoint).** Route → handler → service → … → sink. Use when the
  interesting thing is a *missing guard* rather than a dangerous call, since "nothing is there" has no
  symbol to grep for.
- **Meet in the middle.** Write down the frontier names each walk has reached; when one name appears on
  both lists, you have the path. This is what makes 6-hop chains cheap.

Keep the walk in `work/<slug>/traces/<lead>.md`, three lists:
```
FRONTIER   what I still have to resolve  (name + why it matters)
RESOLVED   file:line -> file:line        (each hop, with the guard state at that hop)
BLOCKED    couldn't resolve + the exact question that would unblock it
```
It survives a context compaction, keeps you from re-walking, and is the first draft of your root-cause
graph. A lead whose `BLOCKED` list is non-empty is `UNCONFIRMED` — name the unresolved hop.

## 2. The five questions, and the grep that answers each

**Q1 — Who calls this?** (bottom-up hop)
```bash
rg -n "\bfuncname\s*\(" --glob '!*test*'          # direct calls
rg -n "[\"']funcname[\"']"                        # registry/config/string dispatch
rg -n "\.funcname\b"                              # method / attribute call
rg -n "funcname" --glob '*.yaml' --glob '*.json' --glob '*.toml'   # config-named handler
```
If Q1 returns nothing but the definition, the caller is dynamic — go to §3.

**Q2 — What does this call actually run?** (resolving dispatch)
- `self.method()` → find the class, then **every subclass**: `rg -n "class \w+\(.*BaseName"` — then check
  each one for an **override**. The override that skips the parent's guard is the single most common deep
  bug in this target class.
- `handler(...)` where `handler` is a variable → `rg -n "handler\s*=" ` and every place the container is
  written: `rg -n "REGISTRY\[|\.register\(|@register"`.
- `getattr(obj, name)(...)` / `globals()[name]` / `importlib.import_module(x)` → find what can reach
  `name`; if `name` is request-derived that is itself the bug (unsafe reflection).
- An interface/protocol/ABC → enumerate implementers, not just the one you read.

**Q3 — What runs before the handler?** (guards you might be crediting or missing)
```bash
rg -n "add_middleware|app\.use\(|@app\.before_request|Depends\(|APIRouter\(|include_router|use[A-Z]\w*Guard|@UseGuards|middleware\s*[:=]"
```
Read the **order**: a guard registered after the route, mounted on a different prefix, or skipped for
`OPTIONS`/`HEAD`/a trailing slash is not protecting what you think.

**Q4 — What does this decorator/dependency actually do?** Read its body, not its name. `@requires_auth`
that only checks a session *exists*, a DI provider that returns a service-account principal, a
`@validate` that validates shape and not authority — all of these read as guards and aren't.

**Q5 — Where does the principal come from *here*?** At every hop ask whether the acting identity is still
threaded through. See §5 — this is how deep authorization bugs are found.

## 3. Indirection catalog — the 12 places a sink hides

| Pattern | Looks like | Resolve by | Usually hides |
|---|---|---|---|
| Base class + override | `self.resolve(name)` | enumerate subclasses, diff each override against the parent | traversal, upload validation, authz |
| Registry / plugin table | `REGISTRY[kind]()` | grep writes: `@register`, `REGISTRY[...] =`, entry_points | any sink, reached by a string from the body |
| Decorator factory | `@guard("read")` | read the factory's returned wrapper | authz (the wrapper checks the wrong thing) |
| DI container / provider | `Depends(get_x)`, NestJS providers | find the provider binding, read what it constructs | principal replaced by a service identity |
| Generic CRUD factory | `make_router(Model)` | read the factory once — it's N routes | missing per-object authz across every model |
| Middleware chain | `app.use(...)` | read registration **order** + path prefixes | auth bypass by prefix/method mismatch |
| Job queue / worker | `enqueue(task, payload)` | find the consumer by task name | principal dropped at the boundary |
| Event bus / signal / hook | `emit("saved")`, `@receiver` | grep the event name as a string | writes that skip the API's checks |
| "Safe" wrapper util | `safe_join`, `sanitize`, `clean_url` | read it, then check **every caller uses it** | the one call site that doesn't |
| Config-named handler | `handler: pkg.mod.Cls` in YAML | grep the string in config files | unreviewed code paths |
| Dynamic import / reflection | `import_module`, `getattr` | trace what can reach the name | RCE, and unroutable-looking routes |
| Cross-language / RPC / MCP | TS calls a Python service | match by route path or message name, not symbol | guard on one side only |

Two compound tells worth memorizing: **a guard defined once and called in most places** (find the caller
that doesn't), and **a parameter named like a value but used like a path/command/template** (`name`,
`key`, `id`, `target`) — the type says string, the sink says filesystem.

## 4. Collapse the indirection at runtime — sink instrumentation (strongest move)

When the static walk is expensive or ambiguous, stop walking and let the interpreter draw the graph.
Patch the sink to print its call stack **only when its argument carries your marker**, then send one
request. No target source is modified.

Write `sitecustomize.py` next to the target's entrypoint:
```python
"""Temporary hunt instrumentation — delete after use. Marker-filtered, read-only."""
import builtins, os, sys
MARK = os.environ.get("SINK_MARK", "deep-probe-9c2f")

def _hit(kind, val):
    print(f"\n=== SINK {kind}: {val!r}", file=sys.stderr)
    f = sys._getframe(2)
    while f:                                     # walk frames, naming the receiver class
        recv = f.f_locals.get("self")
        who = f"   [self={type(recv).__name__}]" if recv is not None else ""
        print(f"  {f.f_code.co_filename}:{f.f_lineno} in {f.f_code.co_name}{who}", file=sys.stderr)
        f = f.f_back
    sys.stderr.flush()

_open = builtins.open
def open(f, *a, **k):                            # path read/write
    if MARK in str(f): _hit("open", f)
    return _open(f, *a, **k)
builtins.open = open

import subprocess                                # command execution
_run = subprocess.Popen.__init__
def run(self, args, *a, **k):
    if MARK in str(args): _hit("subprocess", args)
    return _run(self, args, *a, **k)
subprocess.Popen.__init__ = run
```
**Boot it with `PYTHONPATH=.`** — this is required, not optional: `site` runs *before* the script's
directory joins `sys.path`, so a bare `python app.py` will silently not import your file (verified — the
instrumentation just never fires, which reads exactly like "the sink isn't reachable"). Then send the
marker through the parameter you suspect:
```bash
PORT=8033 SINK_MARK=deep-probe-9c2f PYTHONPATH=. .dynvenv/Scripts/python app.py &
curl -s "$B/export" -d '{"kind":"raw","name":"../../deep-probe-9c2f.txt"}' -H 'Content-Type: application/json'
```
Output — every frame from route to sink, innermost first, **with the concrete class that ran**:
```
=== SINK open: '.../exports/../../deep-probe-9c2f.txt'
  plugins\base.py:22 in run   [self=RawExporter]      <- the override, named at runtime
  app.py:291 in export                                <- the route
```
That is reachability proof, the root-cause graph, and the resolution of the dynamic dispatch, in one
request. The `[self=…]` is what makes it beat a plain `traceback.print_stack()`: it tells you *which*
subclass the registry handed you, which is usually the whole question.

**Limitation, so you don't misread it:** the stack shows frames that are *live at the moment of the sink
call*. A helper that already returned — the `resolve()`/`sanitize()` that computed the argument — will
not appear. Use the `[self=…]` class to jump straight to the right class and read its overrides; or patch
the helper too and diff which call sites reach it. An empty result means "this marker didn't reach this
sink", never "no bug" — check `PYTHONPATH`, the marker string, and that the value isn't transformed
(decoded, normalized, hashed) before the sink.

Extend the same file per class: `pickle.loads`, `yaml.load`, `jinja2.Environment.from_string`,
`requests.Session.request` (SSRF), `shutil.copy`/`Path.write_text` (file write), a cursor's `execute`
(SQLi). For Node, the same idea with `node --require ./sinkspy.js server.js`:
```js
const fs = require("fs"), cp = require("child_process");
const MARK = process.env.SINK_MARK || "deep-probe-9c2f";
for (const [obj, name] of [[fs,"readFileSync"],[fs,"writeFileSync"],[cp,"exec"],[cp,"execSync"]]) {
  const orig = obj[name];
  obj[name] = function (...args) {
    if (String(args[0]).includes(MARK)) console.error(`=== SINK ${name}: ${args[0]}\n`, new Error().stack);
    return orig.apply(this, args);
  };
}
```
**Hygiene:** this is your instrumentation, not the target's behavior — keep it out of the evidence
bundle's "target code" and **delete `sitecustomize.py`/`sinkspy.js` when done** so no later boot is
silently instrumented. Never report a stack from an instrumented run as if it were an app-produced
traceback; label it "instrumented run".

## 5. Deep authorization — where the principal gets lost

Authorization bugs go deep in a specific way: the check exists at the edge, then the identity stops
travelling. Walk the *principal*, not the data, and mark the hop where it disappears:
- **Queue/worker/scheduler** — the payload crosses a serialization boundary; the consumer rebuilds
  context from the payload (attacker-influenced) or from nothing (service identity).
- **Agent tool call** — the dispatcher gets `(name, args)` and no principal (see `vuln-playbooks`).
- **Cache** — a key missing the user/tenant id; the second user gets the first's cached object.
- **Batch/bulk route** — the guard runs on the request, then the loop acts on N ids, checked once or not
  at all; the `/bulk`, `/import`, `/duplicate` sibling of a well-guarded single-object route.
- **Retry / webhook / callback re-entry** — replays the action outside the original request context.
- **Internal HTTP call** — the service calls its own API with an admin token on the user's behalf.
- **ORM hook / signal / trigger** — a `post_save` that writes related rows the API layer never checked.
At each: does a user id / tenant id / role reach the resource access? If not, that's the finding, and its
`file:line` is where the principal was dropped — not where the data was read.

## 6. Budget and stopping rules

Depth is not free. Per lead: ~6 hops or ~10 file reads, then stop and decide.
- **Stop and report** when you have route → … → sink with the guard state known at every hop.
- **Stop and instrument** (§4) when two or more hops are dynamic — cheaper than resolving them by hand.
- **Stop and drop** when a hop is genuinely unreachable from a request (a CLI/test/migration-only path),
  or when the chain leaves attacker-controllable data behind (a hop replaces the value with a constant,
  an id looked up from a trusted table, an enum-validated field).
- **Stop and record BLOCKED** when you can't resolve dispatch after two attempts. `UNCONFIRMED` with a
  precise question beats a guess, and the question is usually answerable at runtime in one request.
Prefer breadth of *classes* over depth on one lead: every applicable matrix row walked to its first real branch
beats one class walked to hop 9.

## 7. Confirming a deep bug

The deeper the bug, the more the confirmation matters — a maintainer's first reaction to a 5-hop claim is
"that path isn't reachable."
- The **instrumented stack** (§4) is your reachability proof; keep it in the evidence bundle, labeled.
- For a monorepo that won't boot, use the **faithful-harness PoC** (`dynamic-hunt` §3): exec the real
  module chain behind a `TestClient`.
- Quote **each hop's** `file:line` in the report's root-cause graph, in call order, and re-read every one
  at the pinned commit before delivery — deep chains are where stale line numbers hide.
- Sweep the sibling call sites *before* reporting: an override that skips a guard usually has company.

Finish with the **reasoning-checklist**; a deep lead that fails item 1 (exploitability) is a code-reading
exercise, not a finding.
