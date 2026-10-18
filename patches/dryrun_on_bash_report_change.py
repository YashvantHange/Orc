"""Dry-run the staged Bash-drift hook without installing it into tools/hooks/.

Checks the four behaviours that matter:
  1. the seeding run flags nothing (a hook that blocks on a backlog it did not create gets disabled);
  2. it still records the pre-existing stale approvals, informationally;
  3. a steady-state run flags nothing;
  4. a report changed out of band, as a Bash edit would, IS flagged.
Neither the session file nor the real state files are written: all are redirected to a temp dir.
"""
import importlib.util
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(r"C:\Users\Yashvant\Desktop\OpenSource")
sys.path.insert(0, str(ROOT / "tools" / "hooks"))
sys.path.insert(0, str(ROOT / "reports"))

tmp = Path(tempfile.mkdtemp())
touched = []

import _hookutil as H
H.touch_report = lambda session, rel: touched.append(rel)

spec = importlib.util.spec_from_file_location("hookmod", ROOT / "patches" / "on_bash_report_change.py")
mod = importlib.util.module_from_spec(spec)
sys.modules["hookmod"] = mod
spec.loader.exec_module(mod)
mod.MANIFEST = tmp / "report_shas.json"
mod.STALE = tmp / "stale_approvals.json"
mod.read_payload = lambda: {"session_id": "dry-run"}

howto = "reports/SHAKA-C8-001-shaka-player-clearkey-license-pin-bypass/HOW-TO-FILE.md"

print("--- run 1: seeding")
mod.main()
print("   flagged:", sorted(touched) or "none")
print("   manifest entries:", len(json.loads(mod.MANIFEST.read_text(encoding='utf-8'))))
stale = json.loads(mod.STALE.read_text(encoding="utf-8"))
print("   stale approvals recorded:", stale["count"])
print("   ...including the HOW-TO-FILE I edited by heredoc:", howto in stale["reports"])

print("--- run 2: steady state, nothing changed")
touched.clear()
mod.main()
print("   flagged:", sorted(touched) or "none")

print("--- run 3: a report changed out of band, as a Bash edit would")
victim = ROOT / "reports" / "SHAKA-C9-001-shaka-player-mpd-query-credential-exfiltration" / "HOW-TO-FILE.md"
original = victim.read_bytes()
try:
    victim.write_bytes(original + b"\n<!-- drift probe -->\n")
    touched.clear()
    mod.main()
    rel = victim.relative_to(ROOT).as_posix()
    print("   flagged:", sorted(touched))
    print("   caught the Bash-style edit:", rel in touched)
finally:
    victim.write_bytes(original)
    print("   victim restored, bytes match:", victim.read_bytes() == original)

print("--- run 4: a brand new report appearing out of band")
newf = ROOT / "reports" / "ZZ-drift-probe" / "ZZ-drift-probe.md"
try:
    newf.parent.mkdir(parents=True, exist_ok=True)
    newf.write_text("# drift probe\n", encoding="utf-8")
    touched.clear()
    mod.main()
    print("   flagged:", sorted(touched))
    print("   caught the new file:", newf.relative_to(ROOT).as_posix() in touched)
finally:
    newf.unlink(missing_ok=True)
    newf.parent.rmdir()
    print("   probe removed, gone:", not newf.exists())
