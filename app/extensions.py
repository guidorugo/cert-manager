from flask import g
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
login_manager = LoginManager()

login_manager.login_view = "auth.login"
login_manager.login_message_category = "warning"


class ConditionalCSRFProtect(CSRFProtect):
    """CSRFProtect subclass that skips CSRF validation for Basic Auth requests."""

    def protect(self):
        if getattr(g, "basic_auth_used", False):
            return
        return super().protect()


csrf = ConditionalCSRFProtect()
