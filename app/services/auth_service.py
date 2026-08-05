"""Shared authentication for username/password logins.

Order: local database first — so the bootstrap admin keeps working even when
the directory is down — then LDAP when LDAP_ENABLED is true. Local accounts
never fall through to LDAP, so a directory entry cannot shadow the
break-glass admin.

Follows the audit_service convention: may log audit entries but never
commits; callers commit as part of their transaction.
"""
from dataclasses import dataclass
from typing import Optional

from flask import current_app
from werkzeug.security import generate_password_hash

from ..extensions import db
from ..models.user import User
from . import audit_service, ldap_service
from .ldap_service import LdapUnavailableError

# Failure reasons returned in AuthResult.reason
REASON_INVALID = "invalid_credentials"
REASON_DEACTIVATED = "account_deactivated"
REASON_LDAP_UNREACHABLE = "ldap_unreachable"
REASON_LDAP_NO_ROLE = "ldap_no_role"


@dataclass
class AuthResult:
    user: Optional[User]
    reason: Optional[str]  # None on success
    auth_method: str  # "local" or "ldap"

    @property
    def ok(self):
        return self.user is not None and self.reason is None


def authenticate(username, password):
    """Authenticate a username/password pair. Returns an AuthResult."""
    if not username or not password:
        _burn_hash()
        return AuthResult(None, REASON_INVALID, "local")

    user = User.query.filter_by(username=username).first()

    # Local accounts authenticate locally only.
    if user is not None and user.auth_source == "local":
        if not user.check_password(password):
            return AuthResult(None, REASON_INVALID, "local")
        if not user.is_active:
            return AuthResult(user, REASON_DEACTIVATED, "local")
        return AuthResult(user, None, "local")

    if not current_app.config.get("LDAP_ENABLED"):
        # Unknown user, or an LDAP-provisioned user with LDAP now disabled.
        _burn_hash()
        return AuthResult(None, REASON_INVALID, "local")

    try:
        ldap_result = ldap_service.authenticate_ldap(username, password)
    except LdapUnavailableError:
        return AuthResult(None, REASON_LDAP_UNREACHABLE, "ldap")

    if ldap_result is None:
        return AuthResult(None, REASON_INVALID, "ldap")

    role = _map_role(ldap_result.groups)
    if role is None:
        return AuthResult(None, REASON_LDAP_NO_ROLE, "ldap")

    if user is None:
        user = _provision_user(username, role, ldap_result.dn)
    else:
        _sync_role(user, role)

    if not user.is_active:
        # Local deactivation always wins over directory state.
        return AuthResult(user, REASON_DEACTIVATED, "ldap")

    return AuthResult(user, None, "ldap")


def _burn_hash():
    """Equalize response timing when no real hash comparison happens."""
    generate_password_hash("dummy-password")


def _map_role(groups):
    """Map LDAP group DNs to an application role.

    - Member of LDAP_ADMIN_GROUP_DN -> admin
    - Member of LDAP_REQUESTER_GROUP_DN -> csr_requester
    - LDAP_REQUESTER_GROUP_DN set but user in neither group -> None
      (rejected); the requester group acts as a required-membership gate.
    - No requester group configured -> csr_requester by default.
    """
    admin_group = (current_app.config.get("LDAP_ADMIN_GROUP_DN") or "").strip().lower()
    requester_group = (current_app.config.get("LDAP_REQUESTER_GROUP_DN") or "").strip().lower()

    if admin_group and admin_group in groups:
        return "admin"
    if requester_group:
        return "csr_requester" if requester_group in groups else None
    return "csr_requester"


def _provision_user(username, role, dn):
    user = User(username=username, role=role, auth_source="ldap")
    user.set_unusable_password()
    db.session.add(user)
    db.session.flush()  # assign user.id for the audit log target
    audit_service.log_action(
        "ldap_user_provisioned",
        target_type="user",
        target_id=user.id,
        details={"username": username, "role": role, "dn": dn},
    )
    return user


def _sync_role(user, role):
    if user.role == role:
        return
    old_role = user.role
    user.role = role
    audit_service.log_action(
        "ldap_role_synced",
        target_type="user",
        target_id=user.id,
        details={"username": user.username, "old_role": old_role, "new_role": role},
    )
