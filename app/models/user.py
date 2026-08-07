from datetime import datetime, timezone

from flask import g
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from ..extensions import db, login_manager

# Sentinel stored in password_hash for externally-authenticated (LDAP) users.
# Never a valid werkzeug hash, and check_password() short-circuits on it.
UNUSABLE_PASSWORD = "!"


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="csr_requester")
    is_active_user = db.Column(db.Boolean, nullable=False, default=True)
    auth_source = db.Column(db.String(10), nullable=False, default="local")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    # D1: brute-force lockout for local accounts.
    failed_login_count = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    # Force a password change on next login (set for the bootstrap admin created
    # from ADMIN_PASSWORD, so the seed credential can't become permanent).
    must_change_password = db.Column(db.Boolean, nullable=False, default=False)

    @property
    def is_active(self):
        return self.is_active_user

    @property
    def is_admin(self):
        return self.role == "admin"

    @property
    def is_csr_requester(self):
        return self.role == "csr_requester"

    @property
    def is_ldap_user(self):
        return self.auth_source == "ldap"

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def set_unusable_password(self):
        """Mark the account as externally authenticated (no local password)."""
        self.password_hash = UNUSABLE_PASSWORD

    def has_usable_password(self):
        return self.password_hash != UNUSABLE_PASSWORD

    def check_password(self, password):
        if not self.has_usable_password():
            return False
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.username}>"


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@login_manager.request_loader
def load_user_from_request(request):
    """Load user from Basic Auth header (set by before_request handler)."""
    return getattr(g, "basic_auth_user", None)
