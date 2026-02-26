from datetime import datetime, timezone

from ..extensions import db


class Certificate(db.Model):
    __tablename__ = "certificates"

    id = db.Column(db.Integer, primary_key=True)
    serial_number = db.Column(db.String(100), unique=True, nullable=False)
    common_name = db.Column(db.String(200), nullable=False)
    subject_json = db.Column(db.Text, nullable=False)
    certificate_pem = db.Column(db.Text, nullable=False)
    private_key_enc = db.Column(db.LargeBinary, nullable=True)
    ca_id = db.Column(db.Integer, db.ForeignKey("certificate_authorities.id"), nullable=False)
    key_type = db.Column(db.String(10), nullable=False)
    key_size = db.Column(db.Integer, nullable=False)
    not_before = db.Column(db.DateTime, nullable=False)
    not_after = db.Column(db.DateTime, nullable=False)
    san_json = db.Column(db.Text, nullable=True)
    key_usage_json = db.Column(db.Text, nullable=True)
    extended_key_usage_json = db.Column(db.Text, nullable=True)
    is_revoked = db.Column(db.Boolean, default=False)
    revoked_at = db.Column(db.DateTime, nullable=True)
    revocation_reason = db.Column(db.String(50), nullable=True)
    requested_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    requester = db.relationship("User", backref="certificates", foreign_keys=[requested_by])

    def __repr__(self):
        return f"<Certificate {self.common_name} ({self.serial_number})>"
