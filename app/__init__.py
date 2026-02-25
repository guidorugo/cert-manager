import os

from flask import Flask

from .config import Config
from .extensions import db, login_manager, csrf


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    from .routes.auth import auth_bp
    from .routes.dashboard import dashboard_bp
    from .routes.ca import ca_bp
    from .routes.certificates import certificates_bp
    from .routes.csr import csr_bp
    from .routes.public import public_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(ca_bp)
    app.register_blueprint(certificates_bp)
    app.register_blueprint(csr_bp)
    app.register_blueprint(public_bp)

    with app.app_context():
        from . import models  # noqa: F401
        db.create_all()
        _create_default_admin(app)

    return app


def _create_default_admin(app):
    from .models.user import User

    if User.query.count() == 0:
        admin = User(username=app.config["ADMIN_USERNAME"])
        admin.set_password(app.config["ADMIN_PASSWORD"])
        db.session.add(admin)
        db.session.commit()
