"""Content negotiation helpers so the same routes can serve JSON to API clients
and HTML to browsers."""

from flask import g, jsonify, request


def wants_json():
    """True when the caller is an API client rather than a browser.

    That means it authenticated with HTTP Basic Auth (already flagged on ``g``),
    or it explicitly prefers ``application/json`` over ``text/html`` in its
    Accept header. Browsers send ``text/html`` (and ``*/*`` ties to HTML), so
    they keep getting rendered pages.
    """
    if getattr(g, "basic_auth_used", False):
        return True
    accept = request.accept_mimetypes
    return accept["application/json"] > accept["text/html"]


def api_error(message, status=400):
    """A JSON error body with an HTTP status (mirrors the 401/403 shape)."""
    return jsonify({"error": message}), status
