from flask import Blueprint, render_template
from flask_login import login_required

from ..models.ca import CertificateAuthority
from ..models.certificate import Certificate
from ..models.csr import CertificateSigningRequest

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
@login_required
def index():
    stats = {
        "ca_count": CertificateAuthority.query.count(),
        "cert_count": Certificate.query.count(),
        "cert_active": Certificate.query.filter_by(is_revoked=False).count(),
        "cert_revoked": Certificate.query.filter_by(is_revoked=True).count(),
        "csr_pending": CertificateSigningRequest.query.filter_by(status="pending").count(),
        "csr_total": CertificateSigningRequest.query.count(),
    }
    recent_certs = Certificate.query.order_by(Certificate.created_at.desc()).limit(5).all()
    recent_cas = CertificateAuthority.query.order_by(CertificateAuthority.created_at.desc()).limit(5).all()
    return render_template("dashboard.html", stats=stats, recent_certs=recent_certs, recent_cas=recent_cas)
