import json

from flask import request
from flask_login import current_user

from ..extensions import db
from ..models.audit_log import AuditLog


def log_action(action, target_type=None, target_id=None, details=None):
    """Create an audit log entry. Caller is responsible for db.session.commit()."""
    if current_user and current_user.is_authenticated:
        user_id = current_user.id
        username = current_user.username
    else:
        user_id = None
        username = "anonymous"

    ip_address = request.remote_addr or "unknown"

    entry = AuditLog(
        user_id=user_id,
        username=username,
        action=action,
        target_type=target_type,
        target_id=target_id,
        details=json.dumps(details) if details else None,
        ip_address=ip_address,
    )
    db.session.add(entry)
