#!/usr/bin/env python3
"""
The installer must not break the tools it installs.

Background: `install_pip_tool` probed `python -m <name> --version`. mitmproxy ships no __main__, so
that probe always failed, so every `--with-offensive` run reinstalled mitmproxy - and that reinstall
resolved mitmproxy 11.0.2's declared `pyOpenSSL<=24.3.0`, downgrading pyOpenSSL to a version that
cannot import against cryptography 50. The installer silently broke its own proxy on every run, and
the failure surfaced far away, as `mitmdump` dying at startup.

These tests are cheap and do not install anything.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _installer():
    spec = importlib.util.spec_from_file_location("install_tools",
                                                  ROOT / "tools" / "install_tools.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["install_tools"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_pip_tools_are_probed_by_console_script_not_dash_m():
    """`python -m mitmproxy` is not a thing; probing that way guarantees a false MISSING."""
    it = _installer()
    for name, entry in it.PIP_TOOLS.items():
        assert isinstance(entry, tuple) and len(entry) == 2, (
            f"PIP_TOOLS[{name}] must be (pip spec, console script) so detection probes a real "
            f"entry point rather than `python -m {name}`")

    src = (ROOT / "tools" / "install_tools.py").read_text(encoding="utf-8")
    assert '"-m", spec.split("[")[0], "--version"' not in src, \
        "the `python -m <spec>` probe is back; it reports mitmproxy MISSING forever"


def test_mitmproxy_pin_repair_is_declared():
    """The declared pin is the broken half, so the installer has to override it after installing."""
    it = _installer()
    repairs = it.PIP_PIN_REPAIRS.get("mitmproxy") or []
    assert any("pyOpenSSL" in r for r in repairs), (
        "installing mitmproxy downgrades pyOpenSSL to <=24.3.0, which cannot import against "
        "cryptography 50 - the installer must force it back up afterwards")


def test_detection_requires_the_tool_to_actually_start():
    """Presence on disk is not installation: an entry point that dies on import is not usable."""
    it = _installer()
    assert not it._pip_tool_ok("definitely-not-a-real-tool")


@pytest.mark.skipif(not (ROOT / ".venv").exists(), reason="no project venv")
def test_mitmproxy_is_importable_in_this_venv():
    """The regression itself: if pyOpenSSL gets downgraded again, this is what notices."""
    it = _installer()
    if not it._venv_script("mitmdump").exists():
        pytest.skip("mitmproxy not installed (python tools/install_tools.py --with-offensive)")
    assert it._pip_tool_ok("mitmdump"), (
        "mitmdump is installed but will not start - most likely pyOpenSSL was downgraded to "
        "<=24.3.0 against cryptography 50. Upgrade pyOpenSSL, do not downgrade cryptography.")
