"""LDAP directory authentication.

Pure LDAP logic: verifies credentials against the directory and returns the
user's DN and group memberships. No database access — user provisioning and
role mapping live in auth_service.

Two modes, selected by configuration:
- Direct bind: LDAP_USER_DN_TEMPLATE builds the user's DN from the username
  and binds as that DN. Groups are then read from the user's own entry.
- Search + bind: a service account (LDAP_BIND_DN) searches
  LDAP_USER_SEARCH_BASE with LDAP_USER_FILTER for the user's entry, then a
  second connection binds as the found DN to verify the password.
"""
import logging
import ssl
from dataclasses import dataclass

from flask import current_app

import ldap3
from ldap3.core.exceptions import LDAPBindError, LDAPException
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import escape_rdn

logger = logging.getLogger(__name__)


class LdapUnavailableError(Exception):
    """The directory could not be reached (or the service bind failed)."""


@dataclass
class LdapResult:
    dn: str
    groups: list  # group DNs, lowercased for comparison


def authenticate_ldap(username, password):
    """Verify credentials against the LDAP directory.

    Returns an LdapResult on success, None for bad credentials or unknown
    users. Raises LdapUnavailableError when the directory is unreachable or
    the service account cannot bind, so callers can distinguish "LDAP down"
    from "wrong password".

    An empty (or whitespace-only) password is rejected before any bind is
    attempted: LDAP servers treat a simple bind with an empty password as an
    anonymous bind, which would otherwise "succeed" for any username.
    """
    if not username or not password or not password.strip():
        return None

    server = _build_server()

    template = current_app.config["LDAP_USER_DN_TEMPLATE"]
    if template:
        user_dn = template.format(username=escape_rdn(username))
        conn = _bind_as_user(server, user_dn, password)
        if conn is None:
            return None
        groups = _read_own_groups(conn, user_dn)
        conn.unbind()
        return LdapResult(dn=user_dn, groups=groups)

    user_dn, groups = _search_user(server, username)
    if user_dn is None:
        return None
    conn = _bind_as_user(server, user_dn, password)
    if conn is None:
        return None
    conn.unbind()
    return LdapResult(dn=user_dn, groups=groups)


def _build_server():
    """Build a Server (or failover ServerPool) from LDAP_SERVER_URI."""
    uris = [u.strip() for u in current_app.config["LDAP_SERVER_URI"].split(",") if u.strip()]
    timeout = current_app.config["LDAP_TIMEOUT_SECONDS"]

    tls = None
    uses_tls = any(u.lower().startswith("ldaps://") for u in uris)
    if uses_tls or current_app.config["LDAP_USE_STARTTLS"]:
        validate = ssl.CERT_REQUIRED if current_app.config["LDAP_TLS_VERIFY"] else ssl.CERT_NONE
        tls = ldap3.Tls(
            validate=validate,
            ca_certs_file=current_app.config["LDAP_CA_CERT_FILE"] or None,
        )

    servers = [
        ldap3.Server(uri, tls=tls, connect_timeout=timeout, get_info=ldap3.NONE)
        for uri in uris
    ]
    if len(servers) == 1:
        return servers[0]
    return ldap3.ServerPool(servers, ldap3.FIRST, active=1, exhaust=True)


def _auto_bind_mode():
    if current_app.config["LDAP_USE_STARTTLS"]:
        return ldap3.AUTO_BIND_TLS_BEFORE_BIND
    return ldap3.AUTO_BIND_NO_TLS


def _connect(server, user_dn, password):
    return ldap3.Connection(
        server,
        user=user_dn,
        password=password,
        auto_bind=_auto_bind_mode(),
        receive_timeout=current_app.config["LDAP_TIMEOUT_SECONDS"],
        read_only=True,
        auto_referrals=False,
    )


def _bind_as_user(server, user_dn, password):
    """Bind as the end user. Returns the connection, or None for bad credentials."""
    try:
        return _connect(server, user_dn, password)
    except LDAPBindError:
        return None
    except LDAPException as exc:
        logger.warning("LDAP unavailable during user bind: %s", exc)
        raise LdapUnavailableError(str(exc)) from exc


def _search_user(server, username):
    """Service-account search for the user's DN and groups (search+bind mode).

    Returns (dn, groups) or (None, []). A failed service bind or search is an
    operational error — raised as LdapUnavailableError, never treated as bad
    end-user credentials.
    """
    search_base = current_app.config["LDAP_USER_SEARCH_BASE"]
    search_filter = current_app.config["LDAP_USER_FILTER"].format(
        username=escape_filter_chars(username)
    )
    group_attr = current_app.config["LDAP_GROUP_MEMBER_ATTR"]

    try:
        conn = _connect(
            server,
            current_app.config["LDAP_BIND_DN"],
            current_app.config["LDAP_BIND_PASSWORD"],
        )
        conn.search(
            search_base,
            search_filter,
            search_scope=ldap3.SUBTREE,
            attributes=[group_attr],
        )
        entries = list(conn.entries)
        conn.unbind()
    except LDAPException as exc:
        logger.warning("LDAP unavailable during user search: %s", exc)
        raise LdapUnavailableError(str(exc)) from exc

    if len(entries) != 1:
        if len(entries) > 1:
            logger.warning(
                "LDAP search for %r matched %d entries; rejecting as ambiguous",
                username, len(entries),
            )
        return None, []

    entry = entries[0]
    return entry.entry_dn, _entry_groups(entry, group_attr)


def _read_own_groups(conn, user_dn):
    """Read the user's group attribute from their own entry (direct-bind mode)."""
    group_attr = current_app.config["LDAP_GROUP_MEMBER_ATTR"]
    try:
        found = conn.search(
            user_dn,
            "(objectClass=*)",
            search_scope=ldap3.BASE,
            attributes=[group_attr],
        )
    except LDAPException as exc:
        logger.warning("Could not read %s for %s: %s", group_attr, user_dn, exc)
        return []
    if not found or not conn.entries:
        return []
    return _entry_groups(conn.entries[0], group_attr)


def _entry_groups(entry, group_attr):
    try:
        values = entry[group_attr].values
    except (KeyError, AttributeError):
        return []
    return [str(v).strip().lower() for v in (values or [])]
