"""
Token auth for the ingest endpoint.

The workflow generates its own token on first use and exposes it (plus a ready-made ingest
URL) through the page's own UI - the admin copies that URL straight into BAM's DNS Activity
Logging "HTTP" destination's Output URI field, no out-of-band secret handoff needed.

Query-param token, not the `Authorization` header, is the primary check: many Gateway installs
run Flask under Apache/mod_wsgi, which strips the `Authorization` header before it reaches any
WSGI app unless `WSGIPassAuthorization On` is explicitly set in Apache's own config. Since
that's a platform-wide config change out of scope for a single workflow, the token instead
travels as a `?token=` query parameter on BAM's Output URI (a free-text field, so this works
without any Apache changes). The `Authorization` header is still checked as a fallback in case
a given install does pass it through, but nothing here depends on that working.
"""
import os
import secrets

from flask import Request

from ..utils.constants import DATA_DIR, TOKEN_FILE


def get_or_create_token() -> str:
    if os.path.isfile(TOKEN_FILE):
        with open(TOKEN_FILE, "r", encoding="utf-8") as f:
            token = f.read().strip()
        if token:
            return token
    os.makedirs(DATA_DIR, exist_ok=True)
    token = secrets.token_urlsafe(32)
    with open(TOKEN_FILE, "w", encoding="utf-8") as f:
        f.write(token)
    return token


def check_request(request: Request) -> bool:
    expected = get_or_create_token()

    presented = request.args.get("token")
    if presented and secrets.compare_digest(presented, expected):
        return True

    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        presented = auth_header[len("Bearer "):].strip()
        if secrets.compare_digest(presented, expected):
            return True

    return False
