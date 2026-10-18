# Filament OSS-Fuzz integration — `.filamat` material parser

Two upstream contributions that together unblock every memory-corruption finding on
`google/filament`, which is `TIER_OT1 / SCOPE_OSS_VRP`.

## Why this exists

Google OSS VRP rules for OT0/OT1 repositories:

> All memory corruption vulnerabilities for OT0 and OT1 tier repositories require either exact
> OSS-Fuzz reproduction steps (using an **existing** fuzz target) or an **already merged patch**
> in the target repository.

`google/filament` has neither. `oss-fuzz/projects/filament/project.yaml` is a 404 (re-checked
2026-09-16) and the repository contains no `LLVMFuzzerTestOneInput`. That is why FIL-001 (heap
out-of-bounds **write**, CVSS 7.8) and FIL-002 (three glTF out-of-bounds reads) were closed
unpaid — not because the proof was weak, but because the precondition was unmet.

Google named the remedy directly on the FIL-002 closure:

> If you identify a missing OSS-Fuzz target that aligns with Filament's security model (e.g.,
> handling untrusted glTF input), please submit a patch to the Filament team to integrate the new
> target first before submitting a report.

This bundle is that patch.

## Contents

| Path | Goes to |
|---|---|
| `filament/0001-add-material-parser-fuzz-target.patch` | `google/filament` |
| `oss-fuzz/projects/filament/{project.yaml,Dockerfile,build.sh}` | `google/oss-fuzz` |

The filament-side patch adds:

- `filament/fuzz/material_parser_fuzzer.cpp` — the fuzz target
- `filament/fuzz/standalone_main.cpp` — a replay driver that needs no libFuzzer
- `filament/fuzz/CMakeLists.txt` — both targets, opt-in
- `FILAMENT_ENABLE_FUZZERS` option in the root `CMakeLists.txt` (default `OFF`)
- `add_subdirectory(fuzz)` in `filament/CMakeLists.txt`

Nothing builds unless `-DFILAMENT_ENABLE_FUZZERS=ON` is passed, so the default build is unchanged.

## Design notes

Three decisions are load-bearing; a reviewer should understand them before changing the file.

**1. It fuzzes `MaterialParser`, the real public entry point.** A `.filamat` blob is untrusted
whenever an application loads a material it did not compile — materials inside downloadable asset
bundles, materials received over the network by `libs/viewer`'s `RemoteServer`, or any material
read from a user-chosen path. `MaterialParser(data, size)` takes the raw buffer, needs no `Engine`
and no GPU, which makes it a clean fuzz entry point.

**2. It keeps going after `ERROR_MISSING_BACKEND`.** `parse()` only locates the shader-language
chunk pair. The chunk *decoders* — where the length, count and offset arithmetic lives — do not run
until an accessor asks for a chunk. A minimised crash input typically carries one interface-block
chunk and no shader dictionary, so it never reaches `SUCCESS`. Returning early on anything but
`SUCCESS` would make the target miss exactly the inputs that matter. The target still returns
immediately on `ERROR_OTHER`, where the chunk container itself failed and there is nothing behind
the accessors.

**3. It checks a structural invariant, not just "did it crash".** The FIL-001 defect is a `uint16_t`
offset accumulator in `BufferInterfaceBlock` that wraps mod 65536. The parser then reports a field
offset outside the block it just sized. No fault occurs *in the parser* — the out-of-bounds write
happens later, in whichever consumer trusts those numbers (`FMaterialInstance` sizes its uniform
buffer from `getSize()` and writes at `getFieldOffset()`). A target that only waited for a
sanitizer report would stay silent on this input.

So the target asserts the invariant that makes the block self-consistent: **every field must start
inside the block the parser sized.** Violating it means the parser has handed its caller an
out-of-bounds write. Checking it here attributes the defect to the code that produced it, instead
of surfacing a crash in a different library under a stack that no longer names the parser.

## Verification status

Be precise about this when filing — some of it is proven and some is not.

### Verified on this machine

Environment: WSL2 Ubuntu 26.04, clang 21.1.8, CMake 4.2.3, Ninja 1.13.2, filament at
`2a8018f54d5154ceb1bf7005c6c01b13aa70e7ad`.

```
cmake <src> -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DFILAMENT_ENABLE_FUZZERS=ON -DFILAMENT_SKIP_SAMPLES=ON -DFILAMENT_SKIP_SDL2=ON \
    -DFILAMENT_BUILD_TESTING=OFF -DFILAMENT_SUPPORTS_VULKAN=OFF -DFILAMENT_SUPPORTS_OPENGL=OFF
ninja material_parser_fuzzer_standalone
```

- Configure accepts `FILAMENT_ENABLE_FUZZERS`; the default build is untouched when it is `OFF`.
- `material_parser_fuzzer.cpp` compiles clean and `material_parser_fuzzer_standalone` links.
- **No false positives:** 53 real `.filamat` files (engine-generated materials, `docs/web/assets`,
  `filament/test/test_material.filamat`) all return exit 0.
- **True positive:** both FIL-001 testcases abort with the invariant message and exit 134 (SIGABRT).
- **Control:** the `benign` testcase — same three-field shape, no offset wrap — returns exit 0.

| Input | Exit |
|---|---|
| 53 real materials | 0 |
| `benign.filamat` | 0 |
| `evil.filamat` | 134 (SIGABRT) |
| `far.filamat` | 134 (SIGABRT) |

Observed on `evil.filamat`:

```
BufferInterfaceBlock reported field "pad" at byte offset 144, outside the 112-byte block it sized
(offset=0 stride=4 elements=10)
```

### NOT verified — must be done before filing

- **The libFuzzer link was never completed here.** Ubuntu's `libclang_rt.fuzzer-x86_64.a` is built
  against libstdc++, while filament compiles with `-stdlib=libc++ -static-libstdc++`, so the link
  fails with undefined `std::__cxx11::` references. This is a property of this machine's toolchain,
  not of the patch — OSS-Fuzz's `base-builder` supplies a matching clang and its own
  `$LIB_FUZZING_ENGINE`. It still means the `material_parser_fuzzer` target itself has been
  compiled but not linked; only the standalone replay target was linked and run.
- **The OSS-Fuzz Docker build has not been run** — Docker is not installed on this machine. The
  `Dockerfile` and `build.sh` are written to the standard OSS-Fuzz contract but are untested.

Validate both on a Linux machine with Docker before opening the oss-fuzz PR:

```
python3 infra/helper.py build_image filament
python3 infra/helper.py build_fuzzers --sanitizer address --architecture x86_64 filament
python3 infra/helper.py check_build filament
python3 infra/helper.py reproduce filament material_parser_fuzzer <testcase_path>
```

Do not claim the OSS-Fuzz build works until `check_build` passes.

## Order of operations

1. **PR 1 → `google/filament`**: apply the patch. This is the one that must merge first; the VRP
   rule requires the fuzz target to already exist.
2. **PR 2 → `google/oss-fuzz`**: add `projects/filament/`, after validating the Docker build.
3. Once merged, re-file FIL-001 (and FIL-002) against the now-existing target, using the exact
   `infra/helper.py` command sequence above — that is the format Google checks for.

Note that `build.sh` builds the full `filament` library, which pulls in `matc` and therefore
glslang, SPIRV-Tools, SPIRV-Cross and basisu, because filament compiles its own materials at build
time. The build is correspondingly slow. Linking the real `filament` target was chosen over
hand-picking source files so the fuzzer tracks filament's own dependency graph as it changes.

## Reproducing the testcases

The generator lives in the FIL-001 report folder
(`reports/FIL-001-filament-filamat-heap-oob-write/poc/make_filamat.py`):

```
python3 make_filamat.py evil   evil.filamat
python3 make_filamat.py far    far.filamat
python3 make_filamat.py benign benign.filamat

./material_parser_fuzzer_standalone evil.filamat    # aborts
./material_parser_fuzzer_standalone benign.filamat  # returns 0
```
