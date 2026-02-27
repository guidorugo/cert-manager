import json
import logging
import re

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

logger = logging.getLogger(__name__)


def _safe_filename(name, extension):
    """Sanitize user-provided name for Content-Disposition header."""
    safe = re.sub(r'[^\w.\-]', '_', name)
    return f'attachment; filename="{safe}.{extension}"'

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
        cn = request.form.get("cn", "").strip()
        org = request.form.get("org", "").strip()
        ou = request.form.get("ou", "").strip()
        country = request.form.get("country", "").strip()
        state = request.form.get("state", "").strip()
        locality = request.form.get("locality", "").strip()
        key_type = request.form.get("key_type", "RSA")

        ocsp_server = current_app.config.get("SERVER_NAME_FOR_OCSP", "localhost:5000")
        if ocsp_server == "localhost:5000":
            ocsp_server = request.host
        ocsp_scheme = current_app.config.get("OCSP_URL_SCHEME", "http")

        try:
            ca_id = int(request.form.get("ca_id"))
            key_size = int(request.form.get("key_size", "2048"))
            validity_days = int(request.form.get("validity_days", "365"))
        except (ValueError, TypeError):
            flash("CA ID, key size, and validity days must be valid numbers.", "danger")
            return render_template("certificates/create.html",
                                   cas=CertificateAuthority.query.filter_by(is_revoked=False).all(),
                                   ocsp_scheme=ocsp_scheme, ocsp_server=ocsp_server)
        san_raw = request.form.get("san", "").strip()

        if not cn:
            flash("Common Name is required.", "danger")
            return render_template("certificates/create.html",
                                   cas=CertificateAuthority.query.filter_by(is_revoked=False).all(),
                                   ocsp_scheme=ocsp_scheme, ocsp_server=ocsp_server)

        ca = db.session.get(CertificateAuthority, ca_id)
        if not ca:
            flash("CA not found.", "danger")
            return render_template("certificates/create.html",
                                   cas=CertificateAuthority.query.filter_by(is_revoked=False).all(),
                                   ocsp_scheme=ocsp_scheme, ocsp_server=ocsp_server)

        if ca.is_revoked:
            flash("Cannot issue certificates from a revoked CA.", "danger")
            return render_template("certificates/create.html",
                                   cas=CertificateAuthority.query.filter_by(is_revoked=False).all(),
                                   ocsp_scheme=ocsp_scheme, ocsp_server=ocsp_server)

        subject_attrs = {
            "CN": cn, "O": org, "OU": ou,
            "C": country, "ST": state, "L": locality,
        }
        san_list = [s.strip() for s in san_raw.split("\n") if s.strip()] if san_raw else []
        passphrase = current_app.config["MASTER_PASSPHRASE"]

        # Build OCSP URL and CRL DP URL
        ocsp_url = f"{ocsp_scheme}://{ocsp_server}/public/ocsp/{ca_id}"
        crl_dp_url = request.form.get("crl_dp_url", "").strip()
        if not crl_dp_url:
            crl_dp_url = f"{ocsp_scheme}://{ocsp_server}/public/crl/{ca_id}.crl"

        # Parse Key Usage and Extended Key Usage from checkboxes
        # If no ku_* fields are present at all (e.g. API call), use service defaults
        ku_fields = ["ku_digital_signature", "ku_key_encipherment",
                     "ku_content_commitment", "ku_data_encipherment", "ku_key_agreement"]
        eku_fields = ["eku_serverAuth", "eku_clientAuth", "eku_codeSigning",
                      "eku_emailProtection", "eku_timeStamping", "eku_ocspSigning"]
        has_ku_fields = any(f in request.form for f in ku_fields)
        has_eku_fields = any(f in request.form for f in eku_fields)

        key_usage = None
        extended_key_usage = None

        if has_ku_fields:
            key_usage = {
                "digital_signature": "ku_digital_signature" in request.form,
                "key_encipherment": "ku_key_encipherment" in request.form,
                "content_commitment": "ku_content_commitment" in request.form,
                "data_encipherment": "ku_data_encipherment" in request.form,
                "key_agreement": "ku_key_agreement" in request.form,
            }
            if not any(key_usage.values()):
                flash("At least one Key Usage must be selected.", "danger")
                cas = CertificateAuthority.query.filter_by(is_revoked=False).all()
                return render_template("certificates/create.html", cas=cas,
                                       ocsp_scheme=ocsp_scheme, ocsp_server=ocsp_server)

        if has_eku_fields:
            eku_names = ["serverAuth", "clientAuth", "codeSigning",
                         "emailProtection", "timeStamping", "ocspSigning"]
            extended_key_usage = [name for name in eku_names
                                  if f"eku_{name}" in request.form]

        try:
            certificate = cert_service.create_certificate(
                ca, subject_attrs, san_list, validity_days, passphrase,
                key_type=key_type, key_size=key_size, ocsp_url=ocsp_url,
                key_usage=key_usage, extended_key_usage=extended_key_usage,
                crl_dp_url=crl_dp_url,
            )
            audit_service.log_action("create_certificate", target_type="certificate", target_id=certificate.id)
            db.session.commit()
            flash(f"Certificate '{certificate.common_name}' created.", "success")
            return redirect(url_for("certificates.detail", cert_id=certificate.id))
        except Exception as e:
            logger.exception("Error creating certificate")
            flash("An unexpected error occurred while creating the certificate.", "danger")

    cas = CertificateAuthority.query.all()
    server = current_app.config.get("SERVER_NAME_FOR_OCSP", "localhost:5000")
    if server == "localhost:5000":
        server = request.host
    scheme = current_app.config.get("OCSP_URL_SCHEME", "http")
    return render_template("certificates/create.html", cas=cas,
                           ocsp_scheme=scheme, ocsp_server=server)


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

    subject = json.loads(certificate.subject_json) if certificate.subject_json else {}

    if certificate.key_usage_json:
        key_usage = json.loads(certificate.key_usage_json)
    else:
        key_usage = {
            "digital_signature": True, "key_encipherment": True,
            "content_commitment": False, "data_encipherment": False,
            "key_agreement": False,
        }

    if certificate.extended_key_usage_json:
        extended_key_usage = json.loads(certificate.extended_key_usage_json)
    else:
        extended_key_usage = ["serverAuth", "clientAuth"]

    return render_template("certificates/detail.html", cert=certificate,
                           san_list=san_list, subject=subject,
                           key_usage=key_usage, extended_key_usage=extended_key_usage)


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
            logger.exception("Error revoking certificate")
            flash("An unexpected error occurred while revoking the certificate.", "danger")

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
            headers={"Content-Disposition": _safe_filename(certificate.common_name, "der")},
        )
    elif fmt == "pkcs12":
        passphrase = current_app.config["MASTER_PASSPHRASE"]
        export_password = request.args.get("password", "changeit")
        try:
            data = cert_service.export_pkcs12(certificate, passphrase, export_password)
            return Response(
                data,
                mimetype="application/x-pkcs12",
                headers={"Content-Disposition": _safe_filename(certificate.common_name, "p12")},
            )
        except ValueError as e:
            flash(str(e), "danger")
            return redirect(url_for("certificates.detail", cert_id=cert_id))
    else:
        data = cert_service.export_certificate_pem(certificate)
        return Response(
            data,
            mimetype="application/x-pem-file",
            headers={"Content-Disposition": _safe_filename(certificate.common_name, "pem")},
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
        headers={"Content-Disposition": _safe_filename(certificate.common_name, "key")},
    )
