import json

from flask import (
    Blueprint, render_template, redirect, url_for, flash,
    request, current_app, Response,
)
from flask_login import login_required, current_user

from ..decorators import admin_required
from ..extensions import db
from ..models.ca import CertificateAuthority
from ..models.csr import CertificateSigningRequest
from ..services import csr_service, cert_service, audit_service

csr_bp = Blueprint("csr", __name__, url_prefix="/csr")


@csr_bp.route("/")
@login_required
def list_csrs():
    if current_user.is_admin:
        csrs = CertificateSigningRequest.query.order_by(
            CertificateSigningRequest.created_at.desc()
        ).all()
    else:
        csrs = CertificateSigningRequest.query.filter_by(
            created_by=current_user.id
        ).order_by(CertificateSigningRequest.created_at.desc()).all()
    return render_template("csr/list.html", csrs=csrs)


@csr_bp.route("/create", methods=["GET", "POST"])
@login_required
def create():
    if request.method == "POST":
        mode = request.form.get("mode", "generate")

        if mode == "upload":
            csr_pem = request.form.get("csr_pem", "").strip()
            if not csr_pem:
                flash("CSR PEM data is required.", "danger")
                return render_template("csr/create.html")
            try:
                csr_model = csr_service.import_csr(csr_pem, created_by=current_user.id)
                audit_service.log_action("import_csr", target_type="csr", target_id=csr_model.id)
                db.session.commit()
                flash(f"CSR for '{csr_model.common_name}' imported.", "success")
                return redirect(url_for("csr.detail", csr_id=csr_model.id))
            except Exception as e:
                flash(f"Error importing CSR: {e}", "danger")
        else:
            cn = request.form.get("cn", "").strip()
            org = request.form.get("org", "").strip()
            ou = request.form.get("ou", "").strip()
            country = request.form.get("country", "").strip()
            state = request.form.get("state", "").strip()
            locality = request.form.get("locality", "").strip()
            key_type = request.form.get("key_type", "RSA")
            san_raw = request.form.get("san", "").strip()

            try:
                key_size = int(request.form.get("key_size", "2048"))
            except ValueError:
                flash("Key size must be a valid number.", "danger")
                return render_template("csr/create.html")

            if not cn:
                flash("Common Name is required.", "danger")
                return render_template("csr/create.html")

            subject_attrs = {
                "CN": cn, "O": org, "OU": ou,
                "C": country, "ST": state, "L": locality,
            }
            san_list = [s.strip() for s in san_raw.split("\n") if s.strip()] if san_raw else []
            passphrase = current_app.config["MASTER_PASSPHRASE"]

            try:
                csr_model, key_pem, _ = csr_service.create_csr(
                    subject_attrs, san_list, key_type, key_size, passphrase,
                    created_by=current_user.id,
                )
                audit_service.log_action("create_csr", target_type="csr", target_id=csr_model.id)
                db.session.commit()
                flash(
                    f"CSR for '{csr_model.common_name}' created. "
                    "Download the private key now - it won't be stored.",
                    "warning",
                )
                return render_template(
                    "csr/detail.html", csr=csr_model,
                    key_pem=key_pem.decode() if key_pem else None,
                )
            except Exception as e:
                flash(f"Error creating CSR: {e}", "danger")

    return render_template("csr/create.html")


@csr_bp.route("/<int:csr_id>")
@login_required
def detail(csr_id):
    csr_model = db.session.get(CertificateSigningRequest, csr_id)
    if not csr_model:
        flash("CSR not found.", "danger")
        return redirect(url_for("csr.list_csrs"))

    if not current_user.is_admin and csr_model.created_by != current_user.id:
        flash("You do not have permission to view this CSR.", "danger")
        return redirect(url_for("csr.list_csrs"))

    san_list = json.loads(csr_model.san_json) if csr_model.san_json else []
    return render_template("csr/detail.html", csr=csr_model, san_list=san_list)


@csr_bp.route("/<int:csr_id>/sign", methods=["GET", "POST"])
@admin_required
def sign(csr_id):
    csr_model = db.session.get(CertificateSigningRequest, csr_id)
    if not csr_model:
        flash("CSR not found.", "danger")
        return redirect(url_for("csr.list_csrs"))

    if csr_model.status != "pending":
        flash("This CSR has already been processed.", "warning")
        return redirect(url_for("csr.detail", csr_id=csr_id))

    if request.method == "POST":
        ocsp_server = current_app.config.get("SERVER_NAME_FOR_OCSP", "localhost:5000")
        ocsp_scheme = current_app.config.get("OCSP_URL_SCHEME", "http")

        try:
            ca_id = int(request.form.get("ca_id"))
            validity_days = int(request.form.get("validity_days", "365"))
        except (ValueError, TypeError):
            flash("CA ID and validity days must be valid numbers.", "danger")
            return render_template("csr/sign.html", csr=csr_model,
                                   cas=CertificateAuthority.query.filter_by(is_revoked=False).all(),
                                   ocsp_scheme=ocsp_scheme, ocsp_server=ocsp_server)

        ca = db.session.get(CertificateAuthority, ca_id)
        if not ca:
            flash("CA not found.", "danger")
            return render_template("csr/sign.html", csr=csr_model,
                                   cas=CertificateAuthority.query.filter_by(is_revoked=False).all(),
                                   ocsp_scheme=ocsp_scheme, ocsp_server=ocsp_server)

        if ca.is_revoked:
            flash("Cannot sign CSR with a revoked CA.", "danger")
            return render_template("csr/sign.html", csr=csr_model,
                                   cas=CertificateAuthority.query.filter_by(is_revoked=False).all(),
                                   ocsp_scheme=ocsp_scheme, ocsp_server=ocsp_server)

        passphrase = current_app.config["MASTER_PASSPHRASE"]

        ocsp_url = f"{ocsp_scheme}://{ocsp_server}/public/ocsp/{ca_id}"
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
                return render_template("csr/sign.html", csr=csr_model,
                                       cas=CertificateAuthority.query.filter_by(is_revoked=False).all(),
                                       ocsp_scheme=ocsp_scheme, ocsp_server=ocsp_server)

        if has_eku_fields:
            eku_names = ["serverAuth", "clientAuth", "codeSigning",
                         "emailProtection", "timeStamping", "ocspSigning"]
            extended_key_usage = [name for name in eku_names
                                  if f"eku_{name}" in request.form]

        try:
            certificate = cert_service.sign_csr(
                csr_model, ca, validity_days, passphrase, ocsp_url=ocsp_url,
                key_usage=key_usage, extended_key_usage=extended_key_usage,
                crl_dp_url=crl_dp_url,
            )
            audit_service.log_action("sign_csr", target_type="csr", target_id=csr_id,
                                     details={"certificate_id": certificate.id})
            db.session.commit()
            flash(f"Certificate '{certificate.common_name}' issued.", "success")
            return redirect(url_for("certificates.detail", cert_id=certificate.id))
        except Exception as e:
            flash(f"Error signing CSR: {e}", "danger")

    cas = CertificateAuthority.query.all()
    server = current_app.config.get("SERVER_NAME_FOR_OCSP", "localhost:5000")
    scheme = current_app.config.get("OCSP_URL_SCHEME", "http")
    return render_template("csr/sign.html", csr=csr_model, cas=cas,
                           ocsp_scheme=scheme, ocsp_server=server)


@csr_bp.route("/<int:csr_id>/reject", methods=["POST"])
@admin_required
def reject(csr_id):
    csr_model = db.session.get(CertificateSigningRequest, csr_id)
    if not csr_model:
        flash("CSR not found.", "danger")
        return redirect(url_for("csr.list_csrs"))

    csr_model.status = "rejected"
    audit_service.log_action("reject_csr", target_type="csr", target_id=csr_id)
    db.session.commit()
    flash(f"CSR for '{csr_model.common_name}' rejected.", "info")
    return redirect(url_for("csr.list_csrs"))
