import os
import sys

from flask import Flask, g, jsonify, request, session

from .config import Config
from .extensions import db, login_manager, csrf


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    login_manager.init_app(app)
    _setup_basic_auth(app)
    csrf.init_app(app)

    _check_security(app)
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

    @app.before_request
    def check_basic_auth():
        g.basic_auth_used = False
        g.basic_auth_user = None

        if not app.config.get("BASIC_AUTH_ENABLED", True):
            return

        auth = request.authorization
        if auth is None or auth.type != "basic":
            return

        from .models.user import User
        user = User.authenticate_basic_auth(auth.username, auth.password)

        if user is None:
            from .services.audit_service import log_action, sanitize_username_for_log
            log_action(
                "basic_auth_failed",
                target_type="user",
                details={"username": sanitize_username_for_log(auth.username), "auth_method": "basic_auth"},
            )
            db.session.commit()
            return

        g.basic_auth_used = True
        g.basic_auth_user = user

        from .services.audit_service import log_action
        log_action(
            "basic_auth_success",
            target_type="user",
            target_id=user.id,
            details={"username": user.username, "auth_method": "basic_auth"},
        )
        db.session.commit()

    @login_manager.unauthorized_handler
    def handle_unauthorized():
        if app.config.get("BASIC_AUTH_ENABLED", True) and request.authorization is not None:
            realm = app.config.get("BASIC_AUTH_REALM", "cert-manager")
            response = jsonify({"error": "Invalid credentials."})
            response.status_code = 401
            response.headers["WWW-Authenticate"] = f'Basic realm="{realm}"'
            return response
        return app.login_manager.login_view and _redirect_to_login() or ("Unauthorized", 401)

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


def _setup_security_headers(app):
    """Add security response headers to all responses."""

    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
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

    # Migrate certificate_authorities table
    if "certificate_authorities" in inspector.get_table_names():
        columns = {col["name"] for col in inspector.get_columns("certificate_authorities")}
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
