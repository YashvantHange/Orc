---
name: env
description: >
  Environment + invocation facts for the hunting pipeline (venv path, Windows/MSYS quirks, the
  hunt.py entrypoint). Referenced by every agent/skill so these facts live in exactly one place.
---

# Environment facts (one source of truth)

- **Python:** always invoke with the repo venv: `.venv/Scripts/python.exe` (Windows) — this is what
  every pipeline script expects. Backing venv for launched targets is `.dynvenv` (auto-built).
- **hunt CLI:** `.venv/Scripts/python.exe hunt.py <subcommand>` — the one-call front door to the
  muscle (`scope`, `scan`, `sweep`, `probe`, `web`, `authz`, `authz-scaffold`, `cvss`, `evidence`,
  `validate-report`, `report`, `dup`, `ledger`, `metrics`). Every subcommand has a manual equivalent;
  the CLI just saves tokens and records evidence uniformly. See its `--help`.
- **Exit codes:** `0` success / confirmed · `1` nothing confirmed · `2` usage error ·
  **`3` scope refusal** — the request was outside the authorized scope and **was not sent**. A `3` is
  never something to work around; fix the scope file or stop.
- **Target kinds:** `src` (a local tree), `url` (a live host + a `scope.yml`), `grey` (both). A
  non-loopback `--url` **requires** `--scope` — there is no flag that skips it. `hunt scope --file <f>
  --lint` before the first request; `--check <url>` tests one decision without sending anything.
  Grey-box keeps the **source** slug as the workdir id so existing `file:line` paths keep working.
- **Windows/Git-Bash:** MSYS rewrites a leading-slash arg (e.g. `/api/x`) into a `C:\...` path. Set
  `MSYS_NO_PATHCONV=1` (or use PowerShell) whenever an argument starts with `/`. For Unicode server
  banners set `PYTHONIOENCODING=utf-8 PYTHONUTF8=1` so a splash screen can't crash a boot.
- **Per-target state:** `work/<slug>/` holds everything for one target — `src/` (clone),
  `findings.json` (ranked leads), `profile.json` (recon cache: kind, base_url/origin, commit,
  endpoints, auth model, identities, scope digest — derived once, reused across sessions),
  `dynamic/`, `evidence/`. A live-website target adds `scope.yml` and `web/`:
  `web/transcript.jsonl` (every request sent or refused, with `T#####` ids), `web/endpoints.json`,
  `web/baselines.json`, `web/js/` + `web/js/src/` (bundles and sourcemap-recovered sources),
  `web/screenshots/`, and `web/auth/<identity>.json` (cookie jars and tokens).
  **Credentials live in `web/auth/`, never inline in `profile.json`** — profiles get quoted into
  reports, and a live session token must not ship with one.
- **URL slugs are keyed on the origin**, not the full URL: `https://app.example.com/api/x` and
  `.../api/y` share one workdir. One host, one profile, one transcript.
- **Resume protocol:** on a new session, read `work/<slug>/profile.json` and `state/ledger.json`
  first — do NOT re-derive recon/identities/commit that are already cached there. For a live target
  also re-read `scope.yml` and check the **test window is still open** before sending anything; a
  window that expired since the last session is a stop, not a warning.
