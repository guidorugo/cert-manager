from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp

from ..models.certificate import Certificate
from .crypto_utils import decrypt_private_key


def build_ocsp_response(ocsp_request_der: bytes, ca, passphrase: str) -> bytes:
    ca_cert = x509.load_pem_x509_certificate(ca.certificate_pem.encode())
    ca_key = decrypt_private_key(ca.private_key_enc, passphrase)

    ocsp_req = ocsp.load_der_ocsp_request(ocsp_request_der)
    serial = ocsp_req.serial_number
    serial_hex = format(serial, "x")

    certificate = Certificate.query.filter_by(
        serial_number=serial_hex, ca_id=ca.id
    ).first()

    now = datetime.now(timezone.utc)

    if certificate is None:
        # Unknown certificate
        response = ocsp.OCSPResponseBuilder().build_unsuccessful(
            ocsp.OCSPResponseStatus.UNAUTHORIZED
        )
        return response.public_bytes(serialization.Encoding.DER)

    cert_obj = x509.load_pem_x509_certificate(certificate.certificate_pem.encode())

    if certificate.is_revoked:
        revocation_time = certificate.revoked_at or now
        builder = ocsp.OCSPResponseBuilder().add_response(
            cert=cert_obj,
            issuer=ca_cert,
            algorithm=hashes.SHA256(),
            cert_status=ocsp.OCSPCertStatus.REVOKED,
            this_update=now,
            next_update=None,
            revocation_time=revocation_time,
            revocation_reason=None,
        ).responder_id(ocsp.OCSPResponderEncoding.HASH, ca_cert)
    else:
        builder = ocsp.OCSPResponseBuilder().add_response(
            cert=cert_obj,
            issuer=ca_cert,
            algorithm=hashes.SHA256(),
            cert_status=ocsp.OCSPCertStatus.GOOD,
            this_update=now,
            next_update=None,
            revocation_time=None,
            revocation_reason=None,
        ).responder_id(ocsp.OCSPResponderEncoding.HASH, ca_cert)

    response = builder.sign(ca_key, hashes.SHA256())
    return response.public_bytes(serialization.Encoding.DER)
