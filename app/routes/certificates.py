import json

from flask import (
    Blueprint, render_template, redirect, url_for, flash,
    request, current_app, Response,
)
from flask_login import login_required, current_user

from ..decorators import admin_required
from ..extensions import db
from ..models.ca import CertificateAuthority
from ..models.certificate import Certificate
from ..services import cert_service, crl_service, audit_service

certificates_bp = Blueprint("certificates", __name__, url_prefix="/certificates")


@certificates_bp.route("/")
@login_required
def list_certs():
    if current_user.is_admin:
        certs = Certificate.query.order_by(Certificate.created_at.desc()).all()
    else:
        certs = Certificate.query.filter_by(
            requested_by=current_user.id
        ).order_by(Certificate.created_at.desc()).all()
    return render_template("certificates/list.html", certs=certs)


@certificates_bp.route("/create", methods=["GET", "POST"])
@admin_required
def create():
    if request.method == "POST":
        ca_id = int(request.form.get("ca_id"))
        cn = request.form.get("cn", "").strip()
        org = request.form.get("org", "").strip()
        ou = request.form.get("ou", "").strip()
        country = request.form.get("country", "").strip()
        state = request.form.get("state", "").strip()
        locality = request.form.get("locality", "").strip()
        key_type = request.form.get("key_type", "RSA")
        key_size = int(request.form.get("key_size", "2048"))
        validity_days = int(request.form.get("validity_days", "365"))
        san_raw = request.form.get("san", "").strip()

        if not cn:
            flash("Common Name is required.", "danger")
            return render_template("certificates/create.html",
                                   cas=CertificateAuthority.query.filter_by(is_revoked=False).all())

        ca = db.session.get(CertificateAuthority, ca_id)
        if not ca:
            flash("CA not found.", "danger")
            return render_template("certificates/create.html",
                                   cas=CertificateAuthority.query.filter_by(is_revoked=False).all())

        if ca.is_revoked:
            flash("Cannot issue certificates from a revoked CA.", "danger")
            return render_template("certificates/create.html",
                                   cas=CertificateAuthority.query.filter_by(is_revoked=False).all())

        subject_attrs = {
            "CN": cn, "O": org, "OU": ou,
            "C": country, "ST": state, "L": locality,
        }
        san_list = [s.strip() for s in san_raw.split("\n") if s.strip()] if san_raw else []
        passphrase = current_app.config["MASTER_PASSPHRASE"]

        # Build OCSP URL
        server = current_app.config.get("SERVER_NAME_FOR_OCSP", "localhost:5000")
        ocsp_url = f"http://{server}/public/ocsp/{ca_id}"

        try:
            certificate = cert_service.create_certificate(
                ca, subject_attrs, san_list, validity_days, passphrase,
                key_type=key_type, key_size=key_size, ocsp_url=ocsp_url,
            )
            audit_service.log_action("create_certificate", target_type="certificate", target_id=certificate.id)
            db.session.commit()
            flash(f"Certificate '{certificate.common_name}' created.", "success")
            return redirect(url_for("certificates.detail", cert_id=certificate.id))
        except Exception as e:
            flash(f"Error creating certificate: {e}", "danger")

    cas = CertificateAuthority.query.all()
    return render_template("certificates/create.html", cas=cas)


@certificates_bp.route("/<int:cert_id>")
@login_required
def detail(cert_id):
    certificate = db.session.get(Certificate, cert_id)
    if not certificate:
        flash("Certificate not found.", "danger")
        return redirect(url_for("certificates.list_certs"))

    if not current_user.is_admin and certificate.requested_by != current_user.id:
        flash("You do not have permission to view this certificate.", "danger")
        return redirect(url_for("certificates.list_certs"))

    san_list = json.loads(certificate.san_json) if certificate.san_json else []
    return render_template("certificates/detail.html", cert=certificate, san_list=san_list)


@certificates_bp.route("/<int:cert_id>/revoke", methods=["GET", "POST"])
@admin_required
def revoke(cert_id):
    certificate = db.session.get(Certificate, cert_id)
    if not certificate:
        flash("Certificate not found.", "danger")
        return redirect(url_for("certificates.list_certs"))

    if request.method == "POST":
        reason = request.form.get("reason", "unspecified")
        try:
            crl_service.revoke_certificate(cert_id, reason)
            audit_service.log_action("revoke_certificate", target_type="certificate", target_id=cert_id,
                                     details={"reason": reason})
            db.session.commit()
            flash(f"Certificate '{certificate.common_name}' revoked.", "success")
            return redirect(url_for("certificates.detail", cert_id=cert_id))
        except Exception as e:
            flash(f"Error revoking certificate: {e}", "danger")

    return render_template("certificates/revoke.html", cert=certificate)


@certificates_bp.route("/<int:cert_id>/download")
@login_required
def download(cert_id):
    certificate = db.session.get(Certificate, cert_id)
    if not certificate:
        flash("Certificate not found.", "danger")
        return redirect(url_for("certificates.list_certs"))

    if not current_user.is_admin and certificate.requested_by != current_user.id:
        flash("You do not have permission to download this certificate.", "danger")
        return redirect(url_for("certificates.list_certs"))

    fmt = request.args.get("format", "pem")

    audit_service.log_action("download_certificate", target_type="certificate", target_id=cert_id,
                             details={"format": fmt})
    db.session.commit()

    if fmt == "der":
        data = cert_service.export_certificate_der(certificate)
        return Response(
            data,
            mimetype="application/x-x509-ca-cert",
            headers={"Content-Disposition": f"attachment; filename={certificate.common_name}.der"},
        )
    elif fmt == "pkcs12":
        passphrase = current_app.config["MASTER_PASSPHRASE"]
        export_password = request.args.get("password", "changeit")
        try:
            data = cert_service.export_pkcs12(certificate, passphrase, export_password)
            return Response(
                data,
                mimetype="application/x-pkcs12",
                headers={"Content-Disposition": f"attachment; filename={certificate.common_name}.p12"},
            )
        except ValueError as e:
            flash(str(e), "danger")
            return redirect(url_for("certificates.detail", cert_id=cert_id))
    else:
        data = cert_service.export_certificate_pem(certificate)
        return Response(
            data,
            mimetype="application/x-pem-file",
            headers={"Content-Disposition": f"attachment; filename={certificate.common_name}.pem"},
        )


@certificates_bp.route("/<int:cert_id>/download-key")
@admin_required
def download_key(cert_id):
    certificate = db.session.get(Certificate, cert_id)
    if not certificate:
        flash("Certificate not found.", "danger")
        return redirect(url_for("certificates.list_certs"))

    if not certificate.private_key_enc:
        flash("No private key available for this certificate.", "danger")
        return redirect(url_for("certificates.detail", cert_id=cert_id))

    audit_service.log_action("download_private_key", target_type="certificate", target_id=cert_id)
    db.session.commit()

    passphrase = current_app.config["MASTER_PASSPHRASE"]
    from ..services.crypto_utils import decrypt_private_key
    from cryptography.hazmat.primitives import serialization
    key = decrypt_private_key(certificate.private_key_enc, passphrase)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return Response(
        key_pem,
        mimetype="application/x-pem-file",
        headers={"Content-Disposition": f"attachment; filename={certificate.common_name}.key"},
    )
