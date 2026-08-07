"""Small helpers for turning model fields into JSON-friendly values."""

import json


def iso(dt):
    """A datetime as an ISO-8601 string, or None."""
    return dt.isoformat() if dt else None


def json_or_none(text):
    """Parse a stored JSON text column into an object; None when empty, or the
    raw string if it is not valid JSON (never raises)."""
    if not text:
        return None
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return text
