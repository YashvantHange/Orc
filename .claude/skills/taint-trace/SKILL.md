---
name: taint-trace
description: >
  Manual source-to-sink taint tracing for when CodeQL is unavailable or misses a path. Load when
  confirming that untrusted input reaches a dangerous sink (RCE/SSRF/SSTI/path/XSS) without
  sanitization, and you need to record each hop as evidence.
---

# Manual taint trace procedure

1. **Pick an anchor.** Either a sink from `findings.json` or one you grep for directly (see
   `vuln-playbooks` for the sink list per class).

2. **Identify the source.** Walk *outward* from the sink to find where the value originates. Sources
   in AI/ML tools: HTTP params/body/headers, uploaded files, **model files**, node/tool configs,
   YAML/JSON config, environment-influenced-by-request, and LLM output used downstream.
   If the sink's argument is a **parameter** rather than a request value, the source is several frames
   away and possibly behind dynamic dispatch — switch to `deep-trace` (walk both ends, resolve the
   registry/override/DI, or instrument the sink) instead of guessing the caller. Most real bugs are here.

3. **Record every hop as a root-cause graph.** Note each assignment/function boundary the tainted
   value crosses, as `file:line -> file:line`, but keep the *causal* structure, not just a line list:
   `source → route → middleware → guard/decorator → the missing/wrong check → framework behavior →
   sink` (see `report-standards`). This graph is your reasoning, your report's Root-cause section, and
   your map of where the patch + variants live. Save it as `root_cause.md` in the evidence bundle.

4. **Check sanitization at each hop.** Is there validation, escaping, allow-listing, type coercion,
   or a safe API? If a guard exists, ask the bypass questions:
   - SSRF: does the allow-list resolve DNS once then reuse? miss IPv6-transition / decimal-hex IPs /
     redirects?
   - path: does it normalize `....//`, backslashes, absolute paths, URL-encoding, null bytes? does the
     prefix check run on the **resolved** path (`realpath`) or the raw string? does a `join`/`/` with an
     absolute right operand silently discard the base?
   - file write: is the *destination* sanitized, or only the source name? can the write land somewhere
     that is later imported, executed, re-read as config, or served?
   - upload: which single guard is doing the work — extension, client `Content-Type`, or magic bytes? is
     the type decided by the name but the bytes consumed by a different loader? is there a size **and**
     decompression-ratio ceiling? is the stored file served back from the app's own origin?
   - SSTI/expr: does user data become part of the **template string** or only a value passed to it? is the
     evaluator sandboxed, and is the sandbox escapable (`().__class__`, ctor chains, `lipsum.__globals__`)?
   - command: shell or argv? if argv — can the value start with `-` (argument injection)? does the callee
     re-shell, or read an env var it interprets?
   - deserialization: is the "trusted source" actually enforced?
   - XSS: is output-encoding applied for the exact context (HTML/attr/JS/URL)? and for a **stored** value,
     is the encoding at the render site (where it must be) or only at the write site?
   - authz on the hop: if the value crosses into a background worker/queue/agent tool call, does the
     **principal** cross with it, or does the far side act as the service?

5. **Decide reachability & controllability.** State plainly: is the source attacker-controllable in
   a real request, and does it reach the sink on a real code path (not dead/test code)? If unsure,
   that's an `UNCONFIRMED` — say which hop is uncertain.

6. **Confirm at runtime.** Map the trace to a probe primitive (`hunt probe --primitive <p> --endpoint
   <ep>` or `hunt sweep`; or the manual curl in `marker-conventions`) and run it against a local
   instance. Capture request/response (and any server-log traceback) as evidence. No runtime
   confirmation → do not claim the bug (unless it's a pure-logic bug proven by an airtight trace).

7. **Output** the root-cause graph, the controllability/reachability verdict, the confirming probe
   command + evidence, and the single most surgical fix (which hop to sanitize / which safe API to
   use). Then run the **reasoning-checklist**.
