import os
from datetime import timedelta


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key")
    MASTER_PASSPHRASE = os.environ.get("MASTER_PASSPHRASE", "dev-passphrase")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///cert-manager.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin")
    SERVER_NAME_FOR_OCSP = os.environ.get("SERVER_NAME_FOR_OCSP", "localhost:5000")

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true"

    OCSP_URL_SCHEME = os.environ.get("OCSP_URL_SCHEME", "http")
    PERMANENT_SESSION_LIFETIME = timedelta(
        minutes=int(os.environ.get("SESSION_LIFETIME_MINUTES", "30"))
    )

    RATE_LIMIT_ENABLED = os.environ.get("RATE_LIMIT_ENABLED", "false").lower() == "true"
    RATE_LIMIT_DEFAULT = os.environ.get("RATE_LIMIT_DEFAULT", "60/minute")

    BASIC_AUTH_ENABLED = os.environ.get("BASIC_AUTH_ENABLED", "true").lower() == "true"
    BASIC_AUTH_REALM = os.environ.get("BASIC_AUTH_REALM", "cert-manager")
    # Verified Basic Auth credentials are cached in memory for this many
    # seconds to avoid an LDAP bind / password-hash check per request (0 = off)
    BASIC_AUTH_CACHE_TTL_SECONDS = int(os.environ.get("BASIC_AUTH_CACHE_TTL_SECONDS") or "60")

    # LDAP authentication (optional). docker-compose passes unset variables
    # as empty strings, so vars with non-empty defaults use `or` fallbacks:
    # empty must behave exactly like unset.
    LDAP_ENABLED = os.environ.get("LDAP_ENABLED", "false").lower() == "true"
    LDAP_SERVER_URI = os.environ.get("LDAP_SERVER_URI", "")
    LDAP_USE_STARTTLS = os.environ.get("LDAP_USE_STARTTLS", "false").lower() == "true"
    LDAP_TLS_VERIFY = (os.environ.get("LDAP_TLS_VERIFY") or "true").lower() == "true"
    LDAP_CA_CERT_FILE = os.environ.get("LDAP_CA_CERT_FILE", "")
    LDAP_USER_DN_TEMPLATE = os.environ.get("LDAP_USER_DN_TEMPLATE", "")
    LDAP_BIND_DN = os.environ.get("LDAP_BIND_DN", "")
    LDAP_BIND_PASSWORD = os.environ.get("LDAP_BIND_PASSWORD", "")
    LDAP_USER_SEARCH_BASE = os.environ.get("LDAP_USER_SEARCH_BASE", "")
    LDAP_USER_FILTER = os.environ.get("LDAP_USER_FILTER") or "(uid={username})"
    LDAP_ADMIN_GROUP_DN = os.environ.get("LDAP_ADMIN_GROUP_DN", "")
    LDAP_REQUESTER_GROUP_DN = os.environ.get("LDAP_REQUESTER_GROUP_DN", "")
    LDAP_GROUP_MEMBER_ATTR = os.environ.get("LDAP_GROUP_MEMBER_ATTR") or "memberOf"
    LDAP_TIMEOUT_SECONDS = int(os.environ.get("LDAP_TIMEOUT_SECONDS") or "5")

    _INSECURE_SECRET_KEY = "dev-secret-key"
    _INSECURE_PASSPHRASE = "dev-passphrase"
    _INSECURE_ADMIN_PASSWORD = "admin"
