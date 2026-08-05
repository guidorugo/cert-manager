import re

from flask import Blueprint, Response, current_app, request
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ..extensions import db, csrf
from ..models.ca import CertificateAuthority
from ..services import ocsp_service


def _safe_filename(name, extension):
    """Sanitize user-provided name for Content-Disposition header."""
    safe = re.sub(r'[^\w.\-]', '_', name)
    return f'attachment; filename="{safe}.{extension}"'

public_bp = Blueprint("public", __name__, url_prefix="/public")


@public_bp.route("/crl/<int:ca_id>.crl")
def download_crl_der(ca_id):
    ca = db.session.get(CertificateAuthority, ca_id)
    if not ca:
        return "CA not found", 404
    # C1: the public CRL endpoint is strictly read-only — it serves the cached
    # CRL and never decrypts the CA key or writes to the DB. Keyed CAs get an
    # initial CRL at creation; revocation refreshes it (B2). No cached CRL
    # (e.g. certificate-only CA) → 404.
    if not ca.crl_pem:
        return "CRL not available for this CA", 404
    try:
        crl = x509.load_pem_x509_crl(ca.crl_pem.encode())
        return Response(
            crl.public_bytes(serialization.Encoding.DER),
            mimetype="application/pkix-crl",
            headers={"Content-Disposition": _safe_filename(ca.name, "crl")},
        )
    except Exception:
        current_app.logger.exception("Error serving cached CRL (DER)")
        return "Internal server error", 500


@public_bp.route("/crl/<int:ca_id>.pem")
def download_crl_pem(ca_id):
    ca = db.session.get(CertificateAuthority, ca_id)
    if not ca:
        return "CA not found", 404
    if not ca.crl_pem:  # C1: read-only, see download_crl_der
        return "CRL not available for this CA", 404
    try:
        return Response(
            ca.crl_pem,
            mimetype="application/x-pem-file",
            headers={"Content-Disposition": _safe_filename(ca.name, "crl.pem")},
        )
    except Exception:
        current_app.logger.exception("Error generating CRL (PEM)")
        return "Internal server error", 500


@public_bp.route("/ca/<int:ca_id>.crt")
def download_ca_cert(ca_id):
    ca = db.session.get(CertificateAuthority, ca_id)
    if not ca:
        return "CA not found", 404

    return Response(
        ca.certificate_pem,
        mimetype="application/x-pem-file",
        headers={"Content-Disposition": _safe_filename(ca.name, "crt")},
    )


@public_bp.route("/ocsp/<int:ca_id>", methods=["POST"])
@csrf.exempt
def ocsp_responder(ca_id):
    ca = db.session.get(CertificateAuthority, ca_id)
    if not ca:
        return "CA not found", 404

    passphrase = current_app.config["MASTER_PASSPHRASE"]
    ocsp_request_der = request.get_data()

    try:
        response_der = ocsp_service.build_ocsp_response(ocsp_request_der, ca, passphrase)
        return Response(response_der, mimetype="application/ocsp-response")
    except Exception:
        current_app.logger.exception("OCSP responder error")
        return "Internal server error", 500
