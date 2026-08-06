import os
import sys

from flask import Flask, current_app, g, jsonify, request, session

from .config import Config
from .extensions import db, login_manager, csrf


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # G2: only trust X-Forwarded-* when explicitly told how many proxy hops sit
    # in front (TRUSTED_PROXY_COUNT). Default 0 = directly exposed, use
    # remote_addr as-is so a client cannot spoof its IP via a forged header.
    _hops = app.config.get("TRUSTED_PROXY_COUNT", 0)
    if _hops and _hops > 0:
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(
            app.wsgi_app, x_for=_hops, x_proto=_hops, x_host=_hops, x_port=_hops
        )

    db.init_app(app)
    login_manager.init_app(app)
    _setup_basic_auth(app)
    csrf.init_app(app)

    _check_security(app)
    _validate_ldap_config(app)
    _configure_session(app)
    _setup_security_headers(app)
    _setup_rate_limiting(app)

    from .routes.auth import auth_bp
    from .routes.dashboard import dashboard_bp
    from .routes.ca import ca_bp
    from .routes.certificates import certificates_bp
    from .routes.csr import csr_bp
    from .routes.public import public_bp
    from .routes.users import users_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(ca_bp)
    app.register_blueprint(certificates_bp)
    app.register_blueprint(csr_bp)
    app.register_blueprint(public_bp)
    app.register_blueprint(users_bp)

    with app.app_context():
        from . import models  # noqa: F401
        db.create_all()
        _migrate_schema()
        _create_default_admin(app)

    return app


def _setup_basic_auth(app):
    """Configure HTTP Basic Auth via before_request + unauthorized_handler."""

    from .services.auth_service import CredentialCache
    app.basic_auth_cache = CredentialCache(app.config.get("BASIC_AUTH_CACHE_TTL_SECONDS", 60))

    @app.before_request
    def check_basic_auth():
        g.basic_auth_used = False
        g.basic_auth_user = None
        # g can outlive a single request when an app context is held open
        # around requests (tests do this); never let a previous request's
        # cached Flask-Login user leak into this one.
        g.pop("_login_user", None)

        if not app.config.get("BASIC_AUTH_ENABLED", True):
            return

        auth = request.authorization
        if auth is None or auth.type != "basic":
            return

        from .services import auth_service
        from .services.audit_service import log_action, sanitize_username_for_log

        result = auth_service.authenticate_basic(auth.username, auth.password)

        if not result.ok:
            log_action(
                "basic_auth_failed",
                target_type="user",
                details={
                    "username": sanitize_username_for_log(auth.username),
                    "auth_method": "basic_auth",
                    "reason": result.reason,
                },
            )
            db.session.commit()
            if result.reason == auth_service.REASON_LDAP_UNREACHABLE:
                response = jsonify({"error": "Directory service unavailable."})
                response.status_code = 503
                return response
            return

        g.basic_auth_used = True
        g.basic_auth_user = result.user
        # authenticate_basic() may have written audit entries (LDAP user
        # provisioning / role sync), and audit logging reads current_user —
        # which makes Flask-Login cache the anonymous user for the rest of
        # the request. Drop that cache so the request loader re-runs and
        # picks up g.basic_auth_user.
        g.pop("_login_user", None)

        log_action(
            "basic_auth_success",
            target_type="user",
            target_id=result.user.id,
            details={
                "username": result.user.username,
                "auth_method": "basic_auth",
                "auth_backend": result.auth_method,
            },
        )
        db.session.commit()

    @login_manager.unauthorized_handler
    def handle_unauthorized():
        # login_manager is a module-level singleton, so every create_app()
        # call re-registers this handler. Read config through current_app —
        # not the closed-over app — so the handler always serves the app
        # actually handling the request.
        if current_app.config.get("BASIC_AUTH_ENABLED", True) and request.authorization is not None:
            realm = current_app.config.get("BASIC_AUTH_REALM", "cert-manager")
            response = jsonify({"error": "Invalid credentials."})
            response.status_code = 401
            response.headers["WWW-Authenticate"] = f'Basic realm="{realm}"'
            return response
        return current_app.login_manager.login_view and _redirect_to_login() or ("Unauthorized", 401)

    def _redirect_to_login():
        from flask import flash, redirect, url_for
        flash("Please log in to access this page.", "warning")
        return redirect(url_for(login_manager.login_view, next=request.url))


def _check_security(app):
    """Reject insecure defaults in production."""
    if app.config.get("TESTING") or app.debug:
        return

    insecure_secret = Config._INSECURE_SECRET_KEY
    insecure_passphrase = Config._INSECURE_PASSPHRASE

    if app.config.get("SECRET_KEY") == insecure_secret:
        print("FATAL: SECRET_KEY is set to the insecure default. "
              "Set a strong SECRET_KEY environment variable.", file=sys.stderr)
        sys.exit(1)

    if app.config.get("MASTER_PASSPHRASE") == insecure_passphrase:
        print("FATAL: MASTER_PASSPHRASE is set to the insecure default. "
              "Set a strong MASTER_PASSPHRASE environment variable.", file=sys.stderr)
        sys.exit(1)

    insecure_admin_password = Config._INSECURE_ADMIN_PASSWORD
    if app.config.get("ADMIN_PASSWORD") == insecure_admin_password:
        print("FATAL: ADMIN_PASSWORD is set to the insecure default. "
              "Set a strong ADMIN_PASSWORD environment variable.", file=sys.stderr)
        sys.exit(1)


def _validate_ldap_config(app):
    """Fail fast on an unusable LDAP configuration (runs in every mode)."""
    if not app.config.get("LDAP_ENABLED"):
        return

    def fatal(msg):
        print(f"FATAL: {msg}", file=sys.stderr)
        sys.exit(1)

    if not app.config.get("LDAP_SERVER_URI"):
        fatal("LDAP_ENABLED is true but LDAP_SERVER_URI is not set.")

    template = app.config.get("LDAP_USER_DN_TEMPLATE")
    search_base = app.config.get("LDAP_USER_SEARCH_BASE")

    if template and search_base:
        fatal("Set either LDAP_USER_DN_TEMPLATE (direct bind) or "
              "LDAP_USER_SEARCH_BASE (search+bind), not both.")
    if not template and not search_base:
        fatal("LDAP_ENABLED is true but neither LDAP_USER_DN_TEMPLATE nor "
              "LDAP_USER_SEARCH_BASE is set.")
    if template and "{username}" not in template:
        fatal("LDAP_USER_DN_TEMPLATE must contain a {username} placeholder.")
    if search_base:
        if "{username}" not in app.config.get("LDAP_USER_FILTER", ""):
            fatal("LDAP_USER_FILTER must contain a {username} placeholder.")
        if not app.config.get("LDAP_BIND_DN") or not app.config.get("LDAP_BIND_PASSWORD"):
            fatal("Search+bind mode requires LDAP_BIND_DN and LDAP_BIND_PASSWORD "
                  "(anonymous directory search is not supported).")


def _setup_security_headers(app):
    """Add security response headers to all responses."""

    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        # E2: restrict resource origins, frame embedding, and base URI. Bootstrap
        # is served from jsdelivr; 'unsafe-inline' is retained because several
        # templates use inline <script> and on* handlers — a future step is to
        # nonce those and drop 'unsafe-inline'. object/frame-ancestors are locked
        # down and base-uri is pinned regardless.
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
            "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "connect-src 'self'; "
            "object-src 'none'; base-uri 'self'; frame-ancestors 'none'; "
            "form-action 'self'",
        )
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        # HSTS is ignored by browsers over plain HTTP, so it's safe to always
        # send; it takes effect once the app is served over TLS.
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=63072000; includeSubDomains"
        )
        return response


def _configure_session(app):
    """Set session cookie security flags."""

    @app.before_request
    def make_session_permanent():
        session.permanent = True


def _setup_rate_limiting(app):
    """Set up optional rate limiting if Flask-Limiter is installed and enabled."""
    if not app.config.get("RATE_LIMIT_ENABLED"):
        app.limiter = None
        return

    try:
        from flask_limiter import Limiter
        from flask_limiter.util import get_remote_address
        limiter = Limiter(
            app=app,
            key_func=get_remote_address,
            default_limits=[app.config.get("RATE_LIMIT_DEFAULT", "60/minute")],
            storage_uri="memory://",
        )
        app.limiter = limiter
    except ImportError:
        print("WARNING: RATE_LIMIT_ENABLED is true but Flask-Limiter is not installed. "
              "Install it with: pip install Flask-Limiter", file=sys.stderr)
        app.limiter = None


def _migrate_schema():
    """Add new columns to existing SQLite tables (ALTER TABLE)."""
    from sqlalchemy import inspect, text
    inspector = inspect(db.engine)

    # Migrate users table
    if "users" in inspector.get_table_names():
        columns = {col["name"] for col in inspector.get_columns("users")}
        if "role" not in columns:
            db.session.execute(text(
                "ALTER TABLE users ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'admin'"
            ))
        if "is_active_user" not in columns:
            db.session.execute(text(
                "ALTER TABLE users ADD COLUMN is_active_user BOOLEAN NOT NULL DEFAULT 1"
            ))
        if "auth_source" not in columns:
            db.session.execute(text(
                "ALTER TABLE users ADD COLUMN auth_source VARCHAR(10) NOT NULL DEFAULT 'local'"
            ))

    # Migrate certificate_authorities table
    if "certificate_authorities" in inspector.get_table_names():
        columns = {col["name"] for col in inspector.get_columns("certificate_authorities")}
        if "crl_pem" not in columns:
            db.session.execute(text(
                "ALTER TABLE certificate_authorities ADD COLUMN crl_pem TEXT"
            ))
        if "is_revoked" not in columns:
            db.session.execute(text(
                "ALTER TABLE certificate_authorities ADD COLUMN is_revoked BOOLEAN NOT NULL DEFAULT 0"
            ))
        if "revoked_at" not in columns:
            db.session.execute(text(
                "ALTER TABLE certificate_authorities ADD COLUMN revoked_at DATETIME"
            ))
        if "revocation_reason" not in columns:
            db.session.execute(text(
                "ALTER TABLE certificate_authorities ADD COLUMN revocation_reason VARCHAR(50)"
            ))
        # A1 key-backend columns (existing CAs are software-backed)
        if "key_backend" not in columns:
            db.session.execute(text(
                "ALTER TABLE certificate_authorities ADD COLUMN key_backend VARCHAR(20) NOT NULL DEFAULT 'software'"
            ))
        if "key_label" not in columns:
            db.session.execute(text(
                "ALTER TABLE certificate_authorities ADD COLUMN key_label VARCHAR(200)"
            ))

    # Migrate certificates table
    if "certificates" in inspector.get_table_names():
        columns = {col["name"] for col in inspector.get_columns("certificates")}
        if "requested_by" not in columns:
            db.session.execute(text(
                "ALTER TABLE certificates ADD COLUMN requested_by INTEGER REFERENCES users(id)"
            ))

    # Migrate certificate_signing_requests table
    if "certificate_signing_requests" in inspector.get_table_names():
        columns = {col["name"] for col in inspector.get_columns("certificate_signing_requests")}
        if "created_by" not in columns:
            db.session.execute(text(
                "ALTER TABLE certificate_signing_requests ADD COLUMN created_by INTEGER REFERENCES users(id)"
            ))

    # Migrate csr_user role to csr_requester
    if "users" in inspector.get_table_names():
        db.session.execute(text(
            "UPDATE users SET role = 'csr_requester' WHERE role = 'csr_user'"
        ))

    db.session.commit()


def _create_default_admin(app):
    from .models.user import User

    if User.query.count() == 0:
        admin = User(username=app.config["ADMIN_USERNAME"], role="admin")
        admin.set_password(app.config["ADMIN_PASSWORD"])
        db.session.add(admin)
        db.session.commit()
