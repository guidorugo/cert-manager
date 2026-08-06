from datetime import datetime, timezone

from ..extensions import db


class CertificateAuthority(db.Model):
    __tablename__ = "certificate_authorities"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), unique=True, nullable=False)
    common_name = db.Column(db.String(200), nullable=False)
    serial_number = db.Column(db.String(100), nullable=False)
    certificate_pem = db.Column(db.Text, nullable=False)
    private_key_enc = db.Column(db.LargeBinary, nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey("certificate_authorities.id"), nullable=True)
    is_root = db.Column(db.Boolean, default=True)
    key_type = db.Column(db.String(10), nullable=False)  # RSA or EC
    key_size = db.Column(db.Integer, nullable=False)
    not_before = db.Column(db.DateTime, nullable=False)
    not_after = db.Column(db.DateTime, nullable=False)
    path_length = db.Column(db.Integer, nullable=True)
    crl_number = db.Column(db.Integer, default=0)
    crl_pem = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    is_revoked = db.Column(db.Boolean, default=False)
    revoked_at = db.Column(db.DateTime, nullable=True)
    revocation_reason = db.Column(db.String(50), nullable=True)
    # A1 key-backend: where this CA's signing key lives. "software" (default)
    # = Fernet-encrypted in private_key_enc; "softhsm" = inside a PKCS#11 token
    # (private_key_enc is the empty-bytes sentinel, key material never in memory).
    key_backend = db.Column(db.String(20), nullable=False, default="software")
    key_label = db.Column(db.String(200), nullable=True)

    parent = db.relationship("CertificateAuthority", remote_side=[id], backref="children")
    certificates = db.relationship("Certificate", backref="ca", lazy="dynamic")
    csrs = db.relationship("CertificateSigningRequest", backref="ca", lazy="dynamic")

    @property
    def has_private_key(self):
        """False for CAs imported certificate-only (empty-bytes sentinel).

        Retained for templates/audit that mean "software key material is
        stored". For "can this CA sign?" use `has_signing_key`, which is also
        true for HSM-backed CAs that hold no bytes here.
        """
        return bool(self.private_key_enc)

    @property
    def has_signing_key(self):
        """True if this CA can sign (leaf certs, CRLs, OCSP, sub-CAs).

        Software CAs hold encrypted bytes; HSM CAs hold the key in the token
        (no bytes here). False only for certificate-only imports.
        """
        return self.key_backend == "softhsm" or bool(self.private_key_enc)

    @property
    def is_exportable(self):
        """True only when the private key can be handed out (software + stored).
        HSM keys are non-extractable, so key/PKCS#12 export is refused."""
        return self.key_backend != "softhsm" and bool(self.private_key_enc)

    @classmethod
    def signing_capable(cls):
        """Query for CAs that can sign: not revoked and holding a usable key
        (software bytes present, or key held in an HSM token)."""
        return cls.query.filter_by(is_revoked=False).filter(
            db.or_(cls.key_backend == "softhsm", cls.private_key_enc != b"")
        )

    def __repr__(self):
        return f"<CA {self.name}>"
