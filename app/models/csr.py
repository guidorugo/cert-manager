from datetime import datetime, timezone

from ..extensions import db


class CertificateSigningRequest(db.Model):
    __tablename__ = "certificate_signing_requests"

    id = db.Column(db.Integer, primary_key=True)
    common_name = db.Column(db.String(200), nullable=False)
    subject_json = db.Column(db.Text, nullable=False)
    csr_pem = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default="pending")  # pending/approved/rejected
    ca_id = db.Column(db.Integer, db.ForeignKey("certificate_authorities.id"), nullable=True)
    certificate_id = db.Column(db.Integer, db.ForeignKey("certificates.id"), nullable=True)
    san_json = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    certificate = db.relationship("Certificate", backref="csr")

    def __repr__(self):
        return f"<CSR {self.common_name} ({self.status})>"
