from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, jsonify

from ..decorators import admin_required
from ..extensions import db
from ..models.ca import CertificateAuthority
from ..services import ca_service, crl_service, audit_service

ca_bp = Blueprint("ca", __name__, url_prefix="/ca")

MAX_FILE_SIZE = 64 * 1024  # 64KB


def _get_pem_input(req, textarea_field, file_field):
    """Get PEM input from file upload (preferred) or textarea fallback."""
    uploaded = req.files.get(file_field)
    if uploaded and uploaded.filename:
        data = uploaded.read()
        if len(data) > MAX_FILE_SIZE:
            raise ValueError(f"Uploaded file exceeds 64KB size limit.")
        return data.decode("utf-8").strip()
    return req.form.get(textarea_field, "").strip()


@ca_bp.route("/")
@admin_required
def list_cas():
    cas = CertificateAuthority.query.order_by(CertificateAuthority.created_at.desc()).all()
    return render_template("ca/list.html", cas=cas)


@ca_bp.route("/create", methods=["GET", "POST"])
@admin_required
def create():
    if request.method == "POST":
        mode = request.form.get("mode", "generate")

        if mode == "upload":
            name = request.form.get("name", "").strip()
            if not name:
                flash("CA Name is required.", "danger")
                return render_template("ca/create.html",
                                       cas=CertificateAuthority.query.filter_by(is_revoked=False).all())

            try:
                cert_pem = _get_pem_input(request, "cert_pem", "cert_file")
                key_pem = _get_pem_input(request, "key_pem", "key_file")
            except ValueError as e:
                flash(str(e), "danger")
                return render_template("ca/create.html",
                                       cas=CertificateAuthority.query.filter_by(is_revoked=False).all())

            if not cert_pem:
                flash("Certificate PEM is required.", "danger")
                return render_template("ca/create.html",
                                       cas=CertificateAuthority.query.filter_by(is_revoked=False).all())
            if not key_pem:
                flash("Private Key PEM is required.", "danger")
                return render_template("ca/create.html",
                                       cas=CertificateAuthority.query.filter_by(is_revoked=False).all())

            upload_parent_id = request.form.get("upload_parent_id")
            parent_id = upload_parent_id if upload_parent_id else None
            passphrase = current_app.config["MASTER_PASSPHRASE"]

            try:
                ca = ca_service.import_ca(name, cert_pem, key_pem, passphrase,
                                          parent_id=parent_id)
                audit_service.log_action("import_ca", target_type="ca", target_id=ca.id)
                db.session.commit()
                flash(f"CA '{ca.name}' imported successfully.", "success")
                return redirect(url_for("ca.detail", ca_id=ca.id))
            except ValueError as e:
                flash(str(e), "danger")
            except Exception as e:
                flash(f"Error importing CA: {e}", "danger")

        else:
            # Generate mode - existing logic
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
                                       cas=CertificateAuthority.query.filter_by(is_revoked=False).all())

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
                                               cas=CertificateAuthority.query.filter_by(is_revoked=False).all())
                    ca = ca_service.create_intermediate_ca(
                        name, parent_ca, subject_attrs, key_type, key_size,
                        validity_days, passphrase, path_length=path_length,
                    )
                else:
                    ca = ca_service.create_root_ca(
                        name, subject_attrs, key_type, key_size,
                        validity_days, passphrase, path_length=path_length,
                    )
                audit_service.log_action("create_ca", target_type="ca", target_id=ca.id)
                db.session.commit()
                flash(f"CA '{ca.name}' created successfully.", "success")
                return redirect(url_for("ca.detail", ca_id=ca.id))
            except Exception as e:
                flash(f"Error creating CA: {e}", "danger")

    cas = CertificateAuthority.query.all()
    return render_template("ca/create.html", cas=cas)


@ca_bp.route("/detect-parent", methods=["POST"])
@admin_required
def detect_parent():
    cert_pem = request.form.get("cert_pem", "").strip()
    if not cert_pem:
        return jsonify({"is_self_signed": None, "parent_id": None})

    is_self_signed, parent_id = ca_service.detect_parent_ca(cert_pem)
    return jsonify({"is_self_signed": is_self_signed, "parent_id": parent_id})


@ca_bp.route("/<int:ca_id>")
@admin_required
def detail(ca_id):
    ca = db.session.get(CertificateAuthority, ca_id)
    if not ca:
        flash("CA not found.", "danger")
        return redirect(url_for("ca.list_cas"))
    chain = ca_service.get_ca_chain(ca)
    return render_template("ca/detail.html", ca=ca, chain=chain)


@ca_bp.route("/<int:ca_id>/revoke", methods=["GET", "POST"])
@admin_required
def revoke(ca_id):
    ca = db.session.get(CertificateAuthority, ca_id)
    if not ca:
        flash("CA not found.", "danger")
        return redirect(url_for("ca.list_cas"))

    if ca.is_revoked:
        flash("CA is already revoked.", "warning")
        return redirect(url_for("ca.detail", ca_id=ca.id))

    if request.method == "POST":
        reason = request.form.get("reason", "unspecified")
        try:
            _, certs_revoked, sub_cas_revoked = crl_service.revoke_ca(ca_id, reason)
            audit_service.log_action("revoke_ca", target_type="ca", target_id=ca_id,
                                     details={"reason": reason, "certs_revoked": certs_revoked,
                                              "sub_cas_revoked": sub_cas_revoked})
            db.session.commit()
            msg = f"CA '{ca.name}' revoked."
            if certs_revoked:
                msg += f" {certs_revoked} certificate(s) revoked."
            if sub_cas_revoked:
                msg += f" {sub_cas_revoked} sub-CA(s) revoked."
            flash(msg, "success")
            return redirect(url_for("ca.detail", ca_id=ca.id))
        except Exception as e:
            flash(f"Error revoking CA: {e}", "danger")

    # Count affected items for the confirmation page
    from ..models.certificate import Certificate
    cert_count = Certificate.query.filter_by(ca_id=ca.id, is_revoked=False).count()
    sub_ca_count = _count_active_sub_cas(ca)
    return render_template("ca/revoke.html", ca=ca, cert_count=cert_count, sub_ca_count=sub_ca_count)


def _count_active_sub_cas(ca):
    """Recursively count non-revoked sub-CAs."""
    count = 0
    for child in ca.children:
        if not child.is_revoked:
            count += 1
            count += _count_active_sub_cas(child)
    return count


@ca_bp.route("/<int:ca_id>/crl", methods=["POST"])
@admin_required
def generate_crl(ca_id):
    ca = db.session.get(CertificateAuthority, ca_id)
    if not ca:
        flash("CA not found.", "danger")
        return redirect(url_for("ca.list_cas"))

    if ca.is_revoked:
        flash("Cannot generate CRL for a revoked CA.", "danger")
        return redirect(url_for("ca.detail", ca_id=ca.id))

    passphrase = current_app.config["MASTER_PASSPHRASE"]
    try:
        crl_service.generate_crl(ca, passphrase)
        audit_service.log_action("generate_crl", target_type="ca", target_id=ca.id)
        db.session.commit()
        flash(f"CRL #{ca.crl_number} generated successfully.", "success")
    except Exception as e:
        flash(f"Error generating CRL: {e}", "danger")

    return redirect(url_for("ca.detail", ca_id=ca.id))
