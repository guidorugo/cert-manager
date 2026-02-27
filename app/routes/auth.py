from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash

from ..extensions import db
from ..models.user import User
from ..services import audit_service
from ..services.audit_service import sanitize_username_for_log


def _is_safe_url(target):
    """Reject absolute URLs that redirect off-site."""
    if not target:
        return False
    # Only allow paths starting with a single / (reject // protocol-relative URLs)
    return target.startswith("/") and not target.startswith("//")

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()
        if user is None:
            generate_password_hash("dummy-password")
        if user and user.check_password(password):
            if not user.is_active:
                audit_service.log_action(
                    "login_failure", target_type="user", target_id=user.id,
                    details={"reason": "account_deactivated", "attempted_username": sanitize_username_for_log(username)},
                )
                db.session.commit()
                flash("Your account has been deactivated.", "danger")
                return render_template("auth/login.html")

            login_user(user)
            audit_service.log_action("login_success", target_type="user", target_id=user.id)
            db.session.commit()
            next_page = request.args.get("next")
            if next_page and _is_safe_url(next_page):
                return redirect(next_page)
            return redirect(url_for("dashboard.index"))

        audit_service.log_action(
            "login_failure", target_type="user",
            details={"attempted_username": sanitize_username_for_log(username)},
        )
        db.session.commit()
        flash("Invalid username or password.", "danger")

    return render_template("auth/login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    audit_service.log_action("logout", target_type="user", target_id=current_user.id)
    db.session.commit()
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))
