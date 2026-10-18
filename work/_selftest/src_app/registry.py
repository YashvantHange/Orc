"""Dispatch registry - the indirection that hides the depth-exec sink.

This is the "Registry / plugin table" row of deep-trace's indirection catalog: a string from the
request body selects a callable, so the dangerous code is never named at the call site.
"""
from handlers import render_markdown, render_template, render_text

REGISTRY = {
    "text": render_text,
    "markdown": render_markdown,
    "template": render_template,        # <- the one that matters
}
