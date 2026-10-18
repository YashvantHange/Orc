"""Registered handlers. DELIBERATELY VULNERABLE - see README.md, do not fix."""


def render_text(body):
    return str(body.get("content", ""))


def render_markdown(body):
    return str(body.get("content", "")).replace("\n", "<br>")


def render_template(body):
    """SEED depth-exec (CWE-94).

    Reached only as REGISTRY["template"], never called by name from a route, so a hunter that reads
    the handler and stops sees nothing. eval() on request-controlled content.
    """
    expr = body.get("content", "")
    return eval(expr)                                                  # noqa: S307
