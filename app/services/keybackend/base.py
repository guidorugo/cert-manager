"""Key-backend abstraction (finding A1).

A CA's signing key lives behind a `KeyBackend`. The default `software` backend
keeps today's behaviour exactly (pyca/cryptography + Fernet-encrypted key). A
future `softhsm` backend keeps the private key inside a PKCS#11 token and never
loads it into Python memory.

The signing seam differs by object type because pyca couples build-and-sign and
its builders type-check the private key (so a PKCS#11 key cannot be passed):

- Certificates and CRLs: the caller builds a normal (unsigned) pyca *builder*
  and hands it to `sign_certificate` / `sign_crl`. The software backend calls
  `builder.sign(key)`; an HSM backend signs the builder's TBS bytes with the
  token and swaps the signature in. The TBS is independent of the signer's
  private key, so this reproduces pyca's exact encoding.
- OCSP: pyca refuses to sign an OCSP response unless the signing key matches the
  responder certificate, so the OCSP response is described by parameters and
  each backend assembles it its own way.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from cryptography.x509 import ocsp


@dataclass
class OcspResponseSpec:
    """Everything needed to produce a single-response OCSP answer, independent
    of how it is assembled/signed."""
    subject_cert_der: bytes          # the certificate the status is about
    issuer_cert_der: bytes           # the CA (responder) certificate
    cert_status: "ocsp.OCSPCertStatus"
    this_update: datetime
    next_update: datetime
    revocation_time: Optional[datetime]
    revocation_reason: object        # x509.ReasonFlags or None
    algorithm: object                # hashes.HashAlgorithm mirrored from request


class KeyBackend(ABC):
    """Signs X.509 objects for a CA using that CA's key material."""

    name = "base"

    # -- key lifecycle -------------------------------------------------------
    @abstractmethod
    def generate_ca_key(self, key_type: str, key_size: int, *, label: str, secret=None):
        """Create a CA key. Returns (public_key, key_ref) where key_ref is the
        opaque reference stored on the CA (encrypted bytes for software, a
        token label for HSM). The private key must never be returned. `secret`
        is the encryption passphrase for the software backend; HSM ignores it."""

    @abstractmethod
    def import_ca_key(self, private_key, *, label: str, secret=None):
        """Store an externally-provided private key. Returns key_ref."""

    @abstractmethod
    def load_public_key(self, ca):
        """Return the CA's public key object."""

    # -- signing -------------------------------------------------------------
    @abstractmethod
    def sign_certificate(self, builder, ca, *, secret=None) -> bytes:
        """Sign a pyca CertificateBuilder with the CA's key; return DER."""

    @abstractmethod
    def sign_crl(self, builder, ca, *, secret=None) -> bytes:
        """Sign a pyca CertificateRevocationListBuilder; return DER."""

    @abstractmethod
    def sign_ocsp(self, spec: OcspResponseSpec, ca, *, secret=None) -> bytes:
        """Assemble and sign an OCSP response for `spec`; return DER."""

    # -- capabilities --------------------------------------------------------
    @abstractmethod
    def can_export(self) -> bool:
        """Whether this backend's keys can be exported (software: yes)."""
