"""
web/ — live-website surface enumeration.

For a source target the attack surface comes from `Grep`ping route decorators. For a live host there
is nothing to grep, so this package builds the equivalent over the wire: endpoints, forms, JS bundles
and sourcemaps, API specs, fingerprint, header posture, and the baselines that stop an SPA's
answer-200-to-everything behaviour from manufacturing false positives.

Every request goes through dynamic/scope.py. Nothing here sends a payload — recon is read-only.
The procedure this automates is the `web-recon` skill, which is authoritative; these modules exist to
save keystrokes, not to be the only way the surface can be mapped.
"""
