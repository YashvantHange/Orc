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
- **Native sanitizer toolchain (C/C++ targets).** Verified present on this machine; the
  `native-sanitizer` skill is the procedure, this is the inventory. Re-check with
  `python tools/install_tools.py --check`, which reports it at the end.
  - **MSVC 14.44.35207** at `C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC`,
    with `clang_rt.asan_dynamic-x86_64.dll` beside `cl.exe`, and **Windows SDK 10.0.26100.0**.
    `cl -fsanitize=address` works and its traces come out **fully symbolized** (function, file,
    line). **This is the path for anything that becomes a report** — it is what produced the
    AddressSanitizer output Google OSS VRP triage accepted for `FIL-001`.
  - **WSL2 `Ubuntu-26.04`** with **clang 21.1.8**, cmake and ninja. ASAN, MSAN, TSAN, UBSAN and
    `-fsanitize=fuzzer,address` all build. Use it for cmake/ninja projects and for a project's own
    in-repo libFuzzer targets.
  - **`llvm-symbolizer` is NOT installed**, so **every WSL sanitizer trace is unsymbolized** —
    `invalid path to external symbolizer`, bare addresses, no `file:line`. `addr2line` exists and
    ASAN does not use it. Fix with `sudo apt install llvm-21` inside WSL, or point
    `ASAN_SYMBOLIZER_PATH` at the binary. Until then, do not build report evidence on path B.
  - **Absent:** valgrind, gdb, AFL, honggfuzz, Atheris, jazzer.js, Docker, php/php-fpm/apache2,
    uwsgi. Do not write a step that assumes any of them.
  - **`gunicorn` is INSTALLED and still UNUSABLE.** `.venv/Scripts/gunicorn.exe` exists, and
    invoking it raises `ModuleNotFoundError: No module named 'fcntl'` - `fcntl` is POSIX-only, so
    gunicorn cannot start on Windows at all. It is listed here rather than under Absent because a
    check that tests for the FILE passes while the lane does not work, which is the worse failure.
  - **Worker-pool runtimes** for the cross-request state class (`state-integrity` § S2): **Node**
    `cluster` is built in (node v24.20.0) and is **the only working shape on this machine**.
    **Python is NOT available** - `pip install gunicorn` does not unlock it (see the fcntl note
    above); it is already installed and still cannot run. So Python joins PHP, Java and Go: an S2
    row on any of those targets is `NEEDS_EXTERNAL_SIGNAL`, never `CLEAR`. `dynamic/instrument.py`
    refuses a python pool boot on win32 up front, before it looks for the executable, so the
    refusal does not depend on gunicorn happening to be missing. To get the Python lane, run the
    target under WSL with gunicorn installed there.
  - **win32 scheduling trap:** Node's `cluster` default on Windows sends *every* connection to *one*
    worker (measured: 12 sequential requests reached 1 of 4 workers). Set
    `cluster.schedulingPolicy = cluster.SCHED_RR` to distribute (measured: 4 of 4). Raising the
    worker count is therefore **not** a negative control for an S2 finding.
