from flask import Blueprint, Response, current_app, request

from ..extensions import db, csrf
from ..models.ca import CertificateAuthority
from ..services import crl_service, ocsp_service

public_bp = Blueprint("public", __name__, url_prefix="/public")


@public_bp.route("/crl/<int:ca_id>.crl")
def download_crl_der(ca_id):
    ca = db.session.get(CertificateAuthority, ca_id)
    if not ca:
        return "CA not found", 404

    passphrase = current_app.config["MASTER_PASSPHRASE"]
    try:
        crl_der = crl_service.get_crl_der(ca, passphrase)
        return Response(
            crl_der,
            mimetype="application/pkix-crl",
            headers={"Content-Disposition": f"attachment; filename={ca.name}.crl"},
        )
    except Exception as e:
        return f"Error generating CRL: {e}", 500


@public_bp.route("/crl/<int:ca_id>.pem")
def download_crl_pem(ca_id):
    ca = db.session.get(CertificateAuthority, ca_id)
    if not ca:
        return "CA not found", 404

    passphrase = current_app.config["MASTER_PASSPHRASE"]
    try:
        crl_pem = crl_service.get_crl_pem(ca, passphrase)
        return Response(
            crl_pem,
            mimetype="application/x-pem-file",
            headers={"Content-Disposition": f"attachment; filename={ca.name}.crl.pem"},
        )
    except Exception as e:
        return f"Error generating CRL: {e}", 500


@public_bp.route("/ca/<int:ca_id>.crt")
def download_ca_cert(ca_id):
    ca = db.session.get(CertificateAuthority, ca_id)
    if not ca:
        return "CA not found", 404

    return Response(
        ca.certificate_pem,
        mimetype="application/x-pem-file",
        headers={"Content-Disposition": f"attachment; filename={ca.name}.crt"},
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
    except Exception as e:
        return f"OCSP error: {e}", 500
