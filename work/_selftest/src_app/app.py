"""Routes for the seeded fixture. DELIBERATELY VULNERABLE - see README.md, do not fix."""
import os
import subprocess

from registry import REGISTRY

ALLOWED_FORMATS = ("csv", "json", "pdf")


def run_report(request):
    """SEED coverage-cmdi (CWE-78).

    The sink is right here in the handler, which is what makes this the class-first sweep's bug:
    reading the route is enough to see it.
    """
    name = request["query"].get("name", "")
    return os.system("/usr/bin/reporter --out /tmp/" + name)          # noqa: S605


def run_export(request):
    """NEGATIVE CONTROL - shaped like run_report and correctly defended.

    argv list, shell=False, and the format is checked against an allow-list before use. A hunter
    that reports this is producing a false positive, which is the thing a negative control exists
    to catch.
    """
    fmt = request["query"].get("fmt", "csv")
    if fmt not in ALLOWED_FORMATS:
        raise ValueError(f"unsupported format {fmt!r}")
    return subprocess.run(["/usr/bin/exporter", "--format", fmt], shell=False, check=False)


def run_plugin(request):
    """SEED depth-exec, ENTRY POINT ONLY.

    Nothing dangerous is visible here: a name goes in, a registered callable comes out. The sink is
    two hops away through REGISTRY, so a surface read of this route finds nothing at all. Following
    the registry is the whole point of the depth role.
    """
    kind = request["query"].get("kind", "text")
    handler = REGISTRY.get(kind)
    if handler is None:
        raise KeyError(kind)
    return handler(request["body"])


ROUTES = {"/report": run_report, "/export": run_export, "/plugin": run_plugin}
