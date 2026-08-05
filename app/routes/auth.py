from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user

from ..extensions import db
from ..services import audit_service, auth_service
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

        result = auth_service.authenticate(username, password)

        if result.ok:
            login_user(result.user)
            audit_service.log_action(
                "login_success", target_type="user", target_id=result.user.id,
                details={"auth_method": result.auth_method},
            )
            db.session.commit()
            next_page = request.args.get("next")
            if next_page and _is_safe_url(next_page):
                return redirect(next_page)
            return redirect(url_for("dashboard.index"))

        audit_service.log_action(
            "login_failure", target_type="user",
            target_id=result.user.id if result.user else None,
            details={
                "reason": result.reason,
                "attempted_username": sanitize_username_for_log(username),
                "auth_method": result.auth_method,
            },
        )
        db.session.commit()

        if result.reason == auth_service.REASON_DEACTIVATED:
            flash("Your account has been deactivated.", "danger")
        elif result.reason == auth_service.REASON_LDAP_UNREACHABLE:
            flash("Directory service is unavailable. Try again later or use a local account.", "danger")
        else:
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
