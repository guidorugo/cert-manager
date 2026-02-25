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
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    parent = db.relationship("CertificateAuthority", remote_side=[id], backref="children")
    certificates = db.relationship("Certificate", backref="ca", lazy="dynamic")
    csrs = db.relationship("CertificateSigningRequest", backref="ca", lazy="dynamic")

    def __repr__(self):
        return f"<CA {self.name}>"
