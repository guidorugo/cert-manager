from datetime import datetime, timezone

from flask import g
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from ..extensions import db, login_manager


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="csr_requester")
    is_active_user = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    @property
    def is_active(self):
        return self.is_active_user

    @property
    def is_admin(self):
        return self.role == "admin"

    @property
    def is_csr_requester(self):
        return self.role == "csr_requester"

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.username}>"

    @staticmethod
    def authenticate_basic_auth(username, password):
        """Validate Basic Auth credentials. Returns User or None.

        Performs a dummy hash check for nonexistent users to prevent
        timing-based username enumeration.
        """
        user = User.query.filter_by(username=username).first()
        if user is None:
            # Dummy check to prevent timing attacks revealing valid usernames
            generate_password_hash("dummy-password")
            return None
        if not user.check_password(password):
            return None
        if not user.is_active:
            return None
        return user


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@login_manager.request_loader
def load_user_from_request(request):
    """Load user from Basic Auth header (set by before_request handler)."""
    return getattr(g, "basic_auth_user", None)
