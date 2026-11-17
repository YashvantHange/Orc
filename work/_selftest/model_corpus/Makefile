# model_corpus - build the five fixtures under a sanitizer.
# DO NOT FIX THE BUGS HERE. See README.md.
#
# Default is clang (portable). On Windows, MSVC is the SYMBOLIZED path and the one report evidence
# is built on - `make msvc` prints the exact command, which needs explicit -I/-LIBPATH because the
# shell has no vcvars. See the `native-sanitizer` skill.
#
# Sanitizer choice is load-bearing: fixture A is an UNINITIALISED READ. ASAN faults on it only
# because the garbage is unmapped; MSAN is what names it. `make msan` is the honest build for A.

CC      ?= clang
SAN     ?= address
CFLAGS  ?= -g -O1 -fsanitize=$(SAN) -fno-omit-frame-pointer -Wall -Wextra
FIXTURES = a_vulnerable b_patched c_suspicious d_rolledback e_crossscope
BINS     = $(addsuffix _san,$(FIXTURES))

.PHONY: all run msan msvc clean

all: $(BINS)

%_san: %.c arena.c arena.h
	$(CC) $(CFLAGS) -o $@ $< arena.c

# The three-case convention: the evil input, the benign control, and every safe fixture.
# Only a_vulnerable may fault. Anything else faulting is a corpus regression.
run: all
	@for f in $(BINS); do \
	  ./$$f 2  >/dev/null 2>&1; evil=$$?; \
	  ./$$f 99 >/dev/null 2>&1; benign=$$?; \
	  printf "%-22s evil(oom_after=2) rc=%-4s benign rc=%s\n" $$f $$evil $$benign; \
	done

# MSAN needs every linked object instrumented, which is fine here: two files, no dependencies.
msan:
	$(MAKE) SAN=memory CFLAGS="-g -O1 -fsanitize=memory -fsanitize-memory-track-origins -fno-omit-frame-pointer -Wall"

# MSVC: symbolized ASAN. Needs clang_rt.asan_dynamic-x86_64.dll on PATH or the binary exits
# 3221225781 (0xC0000135) printing nothing - that is the DLL, not the bug.
msvc:
	@echo 'VCT="C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207"'
	@echo 'SDK="C:\Program Files (x86)\Windows Kits\10"; SDKV=10.0.26100.0'
	@echo 'export PATH="$$VCT/bin/Hostx64/x64:$$PATH"'
	@echo 'cl -nologo -W3 -Zi -fsanitize=address a_vulnerable.c arena.c -Fe:a_asan.exe \'
	@echo '   -I"$$VCT\include" -I"$$SDK\Include\$$SDKV\ucrt" -I"$$SDK\Include\$$SDKV\shared" \'
	@echo '   -link -LIBPATH:"$$VCT\lib\x64" -LIBPATH:"$$SDK\Lib\$$SDKV\ucrt\x64" \'
	@echo '         -LIBPATH:"$$SDK\Lib\$$SDKV\um\x64"'

clean:
	rm -f $(BINS) *_asan.exe *.obj *.pdb *.ilk
