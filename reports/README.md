# reports/

This directory is intentionally empty in the published repository.

It holds two different kinds of file, and only one of them is tracked in git:

**Tracked — pipeline machinery**
- `gate.py` — the delivery gate; verifies a report's evidence chain before it can be sent
- `cvss.py` — CVSS 3.1 vector parsing and scoring
- `dup_check.py` — duplicate check against a product's published advisories
- `live_checks.py` — re-verification of a report's own claims against the target
- `verify_patch.py` — confirms a proposed fix actually closes the finding

**Not tracked — research output**
Every generated disclosure report, PoC script, and evidence attachment lands here and is excluded
by `.gitignore`. Findings are embargoed material until the maintainer has shipped a fix and the
advisory is public; they do not belong in a public repository. Keep them local, disclose them
privately (GHSA draft / huntr / `SECURITY.md`), and let the vendor publish.

`hunt.py report <id>` writes here. `hunt.py validate-report <id>` gates what leaves.
