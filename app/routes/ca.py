from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_required

from ..extensions import db
from ..models.ca import CertificateAuthority
from ..services import ca_service, crl_service

ca_bp = Blueprint("ca", __name__, url_prefix="/ca")


@ca_bp.route("/")
@login_required
def list_cas():
    cas = CertificateAuthority.query.order_by(CertificateAuthority.created_at.desc()).all()
    return render_template("ca/list.html", cas=cas)


@ca_bp.route("/create", methods=["GET", "POST"])
@login_required
def create():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        cn = request.form.get("cn", "").strip()
        org = request.form.get("org", "").strip()
        ou = request.form.get("ou", "").strip()
        country = request.form.get("country", "").strip()
        state = request.form.get("state", "").strip()
        locality = request.form.get("locality", "").strip()
        key_type = request.form.get("key_type", "RSA")
        key_size = int(request.form.get("key_size", "2048"))
        validity_days = int(request.form.get("validity_days", "3650"))
        ca_type = request.form.get("ca_type", "root")
        parent_id = request.form.get("parent_id")
        path_length_str = request.form.get("path_length", "").strip()
        path_length = int(path_length_str) if path_length_str else None

        if not name or not cn:
            flash("Name and Common Name are required.", "danger")
            return render_template("ca/create.html",
                                   cas=CertificateAuthority.query.all())

        subject_attrs = {
            "CN": cn, "O": org, "OU": ou,
            "C": country, "ST": state, "L": locality,
        }
        passphrase = current_app.config["MASTER_PASSPHRASE"]

        try:
            if ca_type == "intermediate" and parent_id:
                parent_ca = db.session.get(CertificateAuthority, int(parent_id))
                if not parent_ca:
                    flash("Parent CA not found.", "danger")
                    return render_template("ca/create.html",
                                           cas=CertificateAuthority.query.all())
                ca = ca_service.create_intermediate_ca(
                    name, parent_ca, subject_attrs, key_type, key_size,
                    validity_days, passphrase, path_length=path_length,
                )
            else:
                ca = ca_service.create_root_ca(
                    name, subject_attrs, key_type, key_size,
                    validity_days, passphrase, path_length=path_length,
                )
            flash(f"CA '{ca.name}' created successfully.", "success")
            return redirect(url_for("ca.detail", ca_id=ca.id))
        except Exception as e:
            flash(f"Error creating CA: {e}", "danger")

    cas = CertificateAuthority.query.all()
    return render_template("ca/create.html", cas=cas)


@ca_bp.route("/<int:ca_id>")
@login_required
def detail(ca_id):
    ca = db.session.get(CertificateAuthority, ca_id)
    if not ca:
        flash("CA not found.", "danger")
        return redirect(url_for("ca.list_cas"))
    chain = ca_service.get_ca_chain(ca)
    return render_template("ca/detail.html", ca=ca, chain=chain)


@ca_bp.route("/<int:ca_id>/crl", methods=["POST"])
@login_required
def generate_crl(ca_id):
    ca = db.session.get(CertificateAuthority, ca_id)
    if not ca:
        flash("CA not found.", "danger")
        return redirect(url_for("ca.list_cas"))

    passphrase = current_app.config["MASTER_PASSPHRASE"]
    try:
        crl_service.generate_crl(ca, passphrase)
        flash(f"CRL #{ca.crl_number} generated successfully.", "success")
    except Exception as e:
        flash(f"Error generating CRL: {e}", "danger")

    return redirect(url_for("ca.detail", ca_id=ca.id))
