import hashlib
import threading
import time
from datetime import datetime, timedelta, timezone

from flask import current_app
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp

from ..models.certificate import Certificate
from ..models.ca import CertificateAuthority
from .crypto_utils import decrypt_private_key

OCSP_RESPONSE_VALIDITY_HOURS = 24

# In-memory cache of decrypted CA signing keys so an unauthenticated OCSP
# flood doesn't run 600k-PBKDF2 per request (C1). Keyed by ca.id, guarded by a
# fingerprint of the ciphertext so a re-imported/rotated key invalidates.
_key_cache = {}
_key_cache_lock = threading.Lock()


def _get_ca_signing_key(ca, passphrase):
    try:
        ttl = current_app.config.get("OCSP_KEY_CACHE_TTL_SECONDS", 300)
    except RuntimeError:
        ttl = 0
    if ttl <= 0:
        return decrypt_private_key(ca.private_key_enc, passphrase)
    fingerprint = hashlib.sha256(ca.private_key_enc).digest()
    now = time.monotonic()
    with _key_cache_lock:
        entry = _key_cache.get(ca.id)
        if entry and entry[0] == fingerprint and entry[2] > now:
            return entry[1]
    key = decrypt_private_key(ca.private_key_enc, passphrase)
    with _key_cache_lock:
        _key_cache[ca.id] = (fingerprint, key, time.monotonic() + ttl)
    return key

_ALLOWED_OCSP_HASHES = (
    hashes.SHA1, hashes.SHA224, hashes.SHA256, hashes.SHA384, hashes.SHA512,
)


def _request_hash_algorithm(ocsp_req):
    """Mirror the request's CertID hash algorithm in the response.

    Clients match responses to requests by CertID, which includes the hash
    algorithm. openssl defaults to SHA-1, and always answering with SHA-256
    made such clients report "no status found". Falls back to SHA-256 for
    unsupported algorithms.
    """
    try:
        algorithm = ocsp_req.hash_algorithm
        if isinstance(algorithm, _ALLOWED_OCSP_HASHES):
            return algorithm
    except Exception:
        pass
    return hashes.SHA256()

_REVOCATION_REASONS = {
    "unspecified": x509.ReasonFlags.unspecified,
    "key_compromise": x509.ReasonFlags.key_compromise,
    "ca_compromise": x509.ReasonFlags.ca_compromise,
    "affiliation_changed": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
    "cessation_of_operation": x509.ReasonFlags.cessation_of_operation,
    "certificate_hold": x509.ReasonFlags.certificate_hold,
    "privilege_withdrawn": x509.ReasonFlags.privilege_withdrawn,
    "aa_compromise": x509.ReasonFlags.aa_compromise,
}


def _unauthorized():
    response = ocsp.OCSPResponseBuilder().build_unsuccessful(
        ocsp.OCSPResponseStatus.UNAUTHORIZED
    )
    return response.public_bytes(serialization.Encoding.DER)


def build_ocsp_response(ocsp_request_der: bytes, ca, passphrase: str) -> bytes:
    # A certificate-only CA can never sign a response — return an unsigned
    # UNAUTHORIZED without parsing or decrypting anything.
    if not ca.private_key_enc:
        return _unauthorized()

    # C1: parse the request and look up the subject BEFORE decrypting the CA
    # key. The key decryption (600k PBKDF2) only runs once we know we have a
    # real subject to sign a response about.
    ocsp_req = ocsp.load_der_ocsp_request(ocsp_request_der)
    serial_hex = format(ocsp_req.serial_number, "x")
    algorithm = _request_hash_algorithm(ocsp_req)

    # Look up the serial as a leaf certificate this CA issued, then (B3) as a
    # sub-CA this CA issued — a revoked intermediate must get a REVOKED answer.
    subject = Certificate.query.filter_by(serial_number=serial_hex, ca_id=ca.id).first()
    if subject is None:
        subject = CertificateAuthority.query.filter_by(
            serial_number=serial_hex, parent_id=ca.id
        ).first()

    # Unknown serial — return an unsigned UNAUTHORIZED without touching the key.
    if subject is None:
        return _unauthorized()

    ca_cert = x509.load_pem_x509_certificate(ca.certificate_pem.encode())
    ca_key = _get_ca_signing_key(ca, passphrase)
    cert_obj = x509.load_pem_x509_certificate(subject.certificate_pem.encode())

    now = datetime.now(timezone.utc)
    next_update = now + timedelta(hours=OCSP_RESPONSE_VALIDITY_HOURS)

    if subject.is_revoked:
        revocation_time = subject.revoked_at or now
        reason = _REVOCATION_REASONS.get(
            subject.revocation_reason, x509.ReasonFlags.unspecified
        )
        builder = ocsp.OCSPResponseBuilder().add_response(
            cert=cert_obj,
            issuer=ca_cert,
            algorithm=algorithm,
            cert_status=ocsp.OCSPCertStatus.REVOKED,
            this_update=now,
            next_update=next_update,
            revocation_time=revocation_time,
            revocation_reason=reason,
        ).responder_id(ocsp.OCSPResponderEncoding.HASH, ca_cert)
    else:
        builder = ocsp.OCSPResponseBuilder().add_response(
            cert=cert_obj,
            issuer=ca_cert,
            algorithm=algorithm,
            cert_status=ocsp.OCSPCertStatus.GOOD,
            this_update=now,
            next_update=next_update,
            revocation_time=None,
            revocation_reason=None,
        ).responder_id(ocsp.OCSPResponderEncoding.HASH, ca_cert)

    response = builder.sign(ca_key, hashes.SHA256())
    return response.public_bytes(serialization.Encoding.DER)
