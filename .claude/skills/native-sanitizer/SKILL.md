---
name: native-sanitizer
description: >
  How to build a C/C++ target under a sanitizer on this machine and turn a crash into report-grade
  evidence — which sanitizer catches which defect class (getting this wrong returns a confident false
  negative), the two verified build paths (MSVC ASAN on Windows, clang + cmake/ninja + libFuzzer under
  WSL), the faithful-harness and input-generator templates, crash triage, and the symbolization
  requirement. Load before building any native PoC, and before calling a native class CLEAR.
---

# Native sanitizer work

This pipeline has already landed an ASAN-proven finding: `FIL-001`, a heap out-of-bounds write in
`google/filament`'s `.filamat` parser. Google OSS VRP triage accepted it in scope on exactly this
basis — *"the reporter provided a solid PoC and AddressSanitizer output, which meets our criteria."*
Everything below is that work generalised, so it is a procedure rather than a one-off.

## Pick the sanitizer FIRST — the wrong one reports nothing

| Defect class | Sanitizer |
|---|---|
| Use-after-free, double free, out-of-bounds read/write | **ASAN** (`-fsanitize=address`) |
| Uninitialised state / uninitialised reads | **MSAN** (`-fsanitize=memory`) |
| Integer overflow, alignment, other UB | **UBSAN** (`-fsanitize=undefined`) |
| Races on shared state | **TSAN** (`-fsanitize=thread`) |

**ASAN and MSAN are not interchangeable, and this has been measured here.** A counter that counts a
slot which was never written, then read — the `CVE-2026-109618` shape — is an **in-bounds read of a
live allocation**. ASAN is completely silent on it. MSAN reports
`use-of-uninitialized-value`. So:

> Sweeping an uninitialised-state class under ASAN and recording `CLEAR` is a false negative, not a
> clean result. It is `BLOCKED (wrong instrumentation)` until MSAN has run.

MSAN's catch: it needs **all** linked code instrumented, or uninstrumented dependencies produce false
positives. For a faithful harness linking only a handful of the target's own files this is usually
fine; for a whole application it generally is not. Say which you did.

## Symbolization is part of the evidence

An unsymbolized trace is a column of hex addresses. It does not show the function, the file or the
line, and it is materially weaker than what triage accepted for `FIL-001`. Verified on this machine:

* **MSVC emits fully symbolized traces out of the box** — function names, source files, line numbers.
* **WSL clang does not**, because `llvm-symbolizer` is not installed (`addr2line` is, and ASAN does not
  use it). You get `invalid path to external symbolizer` and addresses only.

So **MSVC is the primary path for anything that will become a report.** Before using a WSL trace as
evidence, install the symbolizer (`sudo apt install llvm-21`, or set `ASAN_SYMBOLIZER_PATH` to its
binary) and re-run. Report the symbolization status in the finding either way.

## Path A — MSVC ASAN on Windows (primary)

Pattern proven by `work/google__filament/evidence/build.sh`. The CRT and SDK include/lib directories
are passed explicitly rather than through `INCLUDE`/`LIB`, so the build does **not** depend on having
run `vcvars64.bat`:

```bash
VCT="${VCT:-/c/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.44.35207}"
SDK="${SDK:-/c/Program Files (x86)/Windows Kits/10}"
SDKV="${SDKV:-10.0.26100.0}"
export PATH="$VCT/bin/Hostx64/x64:$PATH"

cl -nologo -std:c++20 -EHsc -Zi -Od -fsanitize=address \
  -I"$SRC/<target include dirs>" \
  -I"$VCT/include" \
  -I"$SDK/Include/$SDKV/ucrt" -I"$SDK/Include/$SDKV/um" -I"$SDK/Include/$SDKV/shared" \
  harness.cpp "$SRC/<the target's real .cpp files>" \
  -Fe"harness.exe" \
  -link -LIBPATH:"$VCT/lib/x64" \
        -LIBPATH:"$SDK/Lib/$SDKV/ucrt/x64" -LIBPATH:"$SDK/Lib/$SDKV/um/x64"
```

Override `VCT`/`SDK`/`SDKV` from the environment rather than editing them; check the installed
versions first (`hunt scan`'s toolchain check, or `tools/install_tools.py --check`).

## Path B — WSL clang + cmake/ninja, and libFuzzer (secondary)

Pattern proven by `work/google__filament/scripts/asan_build.sh`. Its central lesson, which cost a
build to learn:

> **Inject sanitizers through `CMAKE_C_FLAGS`/`CMAKE_CXX_FLAGS`, the way OSS-Fuzz does — not through
> the project's own option.** A project's `ENABLE_ASAN`-style flag very often only touches its *Debug*
> flags, so a Release build silently comes out uninstrumented and every run looks clean.

```bash
cp -r "/mnt/c/.../work/<slug>/src/fuzz/." "$HOME/<proj>/fuzz/"
sed -i 's/\r$//' "$HOME"/<proj>/fuzz/*.cpp "$HOME"/<proj>/fuzz/CMakeLists.txt   # CRLF from /mnt/c

CC=clang CXX=clang++ cmake -B out/asan -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g" \
    -DCMAKE_CXX_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g" \
    -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" \
    -D<PROJECT>_ENABLE_FUZZERS=ON \
    <-D flags that strip GUI/graphics backends so the build is small>
ninja -C out/asan -j5 <the project's own fuzz targets>
```

Copying into `$HOME` rather than building on `/mnt/c` is deliberate: the Windows mount is slow and
carries CRLF. For a project's in-repo fuzz targets add `-fsanitize=fuzzer`; clang 21.1.8 here builds
`-fsanitize=fuzzer,address` fine.

## The faithful harness

The template is `work/google__filament/evidence/harness.cpp`. The rules that make it evidence rather
than a re-implementation:

* **Link the target's real sources.** Name them in the harness header comment.
* **Reimplement only the one calling function**, verbatim, and say which upstream `file:line` it was
  copied from — `FIL-001`'s harness says *"a verbatim copy of `filament/src/MaterialParser.cpp:512-567`
  … Nothing else is re-derived."* The report quotes the original beside it.
* **The harness is the measurement boundary** and the report must say so. A bug proven only inside a
  harness that bypasses the real caller's validation is not proven.

For an input-driven bug, generate the malformed artifact with a small script —
`evidence/make_filamat.py` is the template — so the crash input is reproducible rather than an opaque
blob committed into the evidence bundle.

## Running it, and the three-case convention

`FIL-001`'s `poc_fil001.sh` runs **three** cases, and this is the house convention:

| Case | Shows |
|---|---|
| `evil` | the defect fires |
| `far` | the distance/offset is **attacker-chosen**, not a fixed accident |
| `benign` | the negative control completes cleanly |

`export ASAN_OPTIONS=continue_on_error=1` when you want all three in one run instead of aborting on
the first report.

**The PoC script must put the MSVC toolchain on PATH, and this is not cosmetic.** An
`cl -fsanitize=address` binary links `clang_rt.asan_dynamic-x86_64.dll` dynamically. Run it without
that DLL reachable and it dies at load with exit `3221225781` (`0xC0000135`, STATUS_DLL_NOT_FOUND) and
**prints nothing at all** — no ASAN report, no crash, just a non-zero exit. Measured here: the same
binary gave a clean symbolized `heap-use-after-free` report with the path set and a silent
`0xC0000135` without it. A maintainer who runs your PoC that way sees a broken artifact, and a hunter
who records that run has evidence of nothing. So every PoC script starts with the line
`poc_fil001.sh` already had:

```bash
VCT="${VCT:-/c/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.44.35207}"
export PATH="$VCT/bin/Hostx64/x64:$PATH"
```

If an exit code is `3221225781`, that is the DLL, not the bug.

## Triage and minimisation

* Minimise the crashing input until every remaining byte is load-bearing; say what each field does.
* Separate **the crash** from **the consequence**. A SEGV on a null page is a crash; an attacker-chosen
  write offset is a consequence. Score the consequence.
* Record the run through `hunt poc-run` so `evidence/runlog.py` captures the command, exit code,
  stdout/stderr and their hashes, plus the target's commit. `verify()` needs `MIN_RUNS = 2` and a clean
  tree, so run the PoC twice from a clean checkout.

## Two hard rules

* **MinGW has no ASAN.** This is not a detail: it is why `FIL-002` shipped with only SIGSEGV and
  exit-code evidence when triage had explicitly named AddressSanitizer output as what met their bar.
  If `cl` or clang is unavailable, the verdict is `BLOCKED`, not a bare crash proof.
* **Check the program's intake rule before building the PoC.** Some programs require an existing
  OSS-Fuzz target or an already-merged patch for memory-corruption reports. Establishing that after
  the harness is built has already cost this pipeline a whole report — see the mistake log.

## What this machine has

Verified present: MSVC 14.44.35207 with `clang_rt.asan_dynamic-x86_64.dll`; Windows SDK
10.0.26100.0; WSL2 Ubuntu-26.04 with clang 21.1.8, cmake, ninja, and ASAN/MSAN/TSAN/UBSAN/libFuzzer
all building.

Verified **absent**: `llvm-symbolizer` (installable as `llvm-21`), valgrind, gdb, AFL, honggfuzz. Do
not write a playbook step that assumes them; `tools/install_tools.py --check` reports the current
state.
