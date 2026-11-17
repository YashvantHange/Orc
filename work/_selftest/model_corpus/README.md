# model_corpus — the five fixtures that decide whether the opening pass is real

**DO NOT FIX THE BUGS IN THIS DIRECTORY, AND DO NOT "IMPROVE" THE SAFE ONES.** Every file here is
input, not code. `tests/test_model_corpus.py` asserts the seeds and the defences are still present,
and a repaired fixture makes the exam untestable.

## Why five and not one

A single vulnerable fixture proves almost nothing. It is passed by any method that learned
`abnormal exit + mutable state = vulnerability`, and that method's real-world output is a flood of
false positives — which `state-integrity`'s own scope gate names as the dominant failure of this
family.

So the corpus is one defect and four ways of being safe, and **the four controls are the test**:

| | File | What it is | Expected verdict |
|---|---|---|---|
| **A** | `a_vulnerable.c` | the real defect: counter incremented before a fallible allocation, destructor walks the counter | **found**, with the right invariant and the right later consumer |
| **B** | `b_patched.c` | A with the real fix — allocate into a local, commit the counter last | **not reported** |
| **C** | `c_suspicious.c` | the same increment-first shape and the same count-walking destructor, but nothing between them can fail | **not reported** |
| **D** | `d_rolledback.c` | the exit *does* fire mid-mutation; a handler in another function un-counts the slot | **not reported** |
| **E** | `e_crossscope.c` | a process-lifetime global *does* hold request-arena memory, and is nulled in the shutdown path | **not reported** |

What each control catches, specifically:

- **B** catches a method that points at a famous function instead of a defect.
- **C** catches a method that matched the *shape* and never asked whether the interrupt can occur
  in that window. Everything a pattern keys on is present in C.
- **D** catches a method that found the window and stopped one question early — *who repairs this?*
  The answer is three lines away in a different function.
- **E** catches a method that read the assignment and never opened the shutdown path. The absence
  of a store is not visible where the store would be.

E also carries a second trap: `request_count` is a global written during a request and is
**correctly** process-scoped. Flagging it confuses "a global written during a request" with "a
global holding request-scoped data".

## The abnormal exit is real

`arena.c`'s allocator does not return `NULL` on failure — it `longjmp`s. A fixture whose failure
path is a checked return value teaches the wrong lesson: this defect class needs a failure that
abandons the caller *mid-statement*, which is what PHP's `zend_bailout` and Apache's abort function
actually do. `arena_alloc` either returns memory or never returns.

`oom_after=N` lets the Nth allocation be the one that fails, so the window is deterministic.

## Building and running

```
make                 # all five, under ASAN (MSVC) — see the `native-sanitizer` skill
make run             # the three-case convention: evil, benign, and each control
```

Measured on this machine (MSVC 14.44.35207, `-fsanitize=address`):

```
a              evil(oom_after=2) rc=1     benign rc=0      <- the only one that faults
b_patched      evil rc=0                  benign rc=0
c_suspicious   evil rc=0                  benign rc=0
d_rolledback   evil rc=0                  benign rc=0
e_crossscope   evil rc=0                  benign rc=0
```

Fixture A faults in `table_destroy` reading a `0xBEBEBEBE…` pointer — an uninitialised slot the
counter claimed existed. Note *what* ASAN says: `access-violation`, not
`use-of-uninitialized-value`. ASAN sees the fault only because the garbage happens to be unmapped;
the defect is an **uninitialised read**, and **MSAN** is the sanitizer that names it. Picking the
wrong one here returns a confident false negative — see `native-sanitizer`.

## The grading key is deliberately not in this directory

The reference invariant set — which invariants a good model must contain, and which later consumer
each one points at — lives in **`tests/data/model_corpus_reference.json`**, outside the fixture
tree, because a hunter reads its target and must not read the answer. Do not copy it here, do not
summarise it here, and do not cite it in a model. If the exam needs the answer to find the answer,
it has measured nothing.
