"""Framework configuration. DELIBERATELY VULNERABLE - see README.md, do not fix."""

DEBUG = True

# SEED stack-debug (CWE-215). A stack surface, not a vulnerability class: the class-first coverage
# matrix has no row that would ever ask "is there a config dump endpoint", which is exactly why the
# stack role reads the platform's own playbook instead.
DEBUG_ENDPOINTS = [
    "/_debug/config",        # dumps DATABASE_URL and SECRET_KEY
    "/_debug/routes",
]

SECRET_KEY = "not-a-real-secret-fixture-only"
DATABASE_URL = "postgresql://fixture:fixture@localhost/fixture"
