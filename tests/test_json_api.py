"""JSON content negotiation: the same routes serve JSON to API clients
(Basic Auth or Accept: application/json) and HTML to browsers."""

import base64

import pytest

from app.models.ca import CertificateAuthority

JSON = {"Accept": "application/json"}
HTML = {"Accept": "text/html"}


def _basic(username, password):
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


# ---- read endpoints -------------------------------------------------------

def test_list_cas_json_via_accept(auth_admin):
    r = auth_admin.get("/ca/", headers=JSON)
    assert r.status_code == 200
    assert r.is_json
    assert isinstance(r.get_json(), list)


def test_list_cas_html_for_browser(auth_admin):
    r = auth_admin.get("/ca/", headers=HTML)
    assert r.status_code == 200
    assert "text/html" in r.content_type


def test_no_accept_header_defaults_to_html(auth_admin):
    r = auth_admin.get("/ca/")
    assert "text/html" in r.content_type


def test_basic_auth_gets_json_automatically(client, admin_user):
    r = client.get("/ca/", headers=_basic("testadmin", "adminpass"))
    assert r.status_code == 200
    assert r.is_json


def test_lists_json(auth_admin):
    for path in ("/ca/", "/certificates/", "/csr/", "/users/"):
        r = auth_admin.get(path, headers=JSON)
        assert r.status_code == 200 and r.is_json, path
        assert isinstance(r.get_json(), list)


def test_audit_log_json_is_paginated(auth_admin):
    r = auth_admin.get("/users/audit-log", headers=JSON)
    assert r.status_code == 200 and r.is_json
    body = r.get_json()
    assert set(body) >= {"items", "page", "total", "pages"}


def test_dashboard_json(auth_admin):
    r = auth_admin.get("/", headers=JSON)
    assert r.status_code == 200 and r.is_json
    assert "stats" in r.get_json()


def test_missing_resource_json_404(auth_admin):
    r = auth_admin.get("/ca/9999", headers=JSON)
    assert r.status_code == 404
    assert r.get_json()["error"]


# ---- write endpoints ------------------------------------------------------

def test_create_ca_via_json(auth_admin):
    r = auth_admin.post("/ca/create", headers=JSON, data={
        "mode": "generate", "name": "apitest", "cn": "API Test CA",
        "key_type": "EC", "key_size": "256", "validity_days": "365",
        "ca_type": "root",
    })
    assert r.status_code == 201
    body = r.get_json()
    assert body["name"] == "apitest"
    assert body["common_name"] == "API Test CA"
    assert isinstance(body["id"], int)
    # secrets never leak
    assert "private_key_enc" not in body


def test_create_ca_validation_error_json(auth_admin):
    r = auth_admin.post("/ca/create", headers=JSON, data={
        "mode": "generate", "name": "", "cn": "",
    })
    assert r.status_code == 400
    assert "error" in r.get_json()


def test_generate_crl_via_json(auth_admin, app):
    auth_admin.post("/ca/create", headers=JSON, data={
        "mode": "generate", "name": "crlca", "cn": "CRL CA",
        "key_type": "EC", "key_size": "256", "validity_days": "365",
        "ca_type": "root",
    })
    with app.app_context():
        ca_id = CertificateAuthority.query.filter_by(name="crlca").first().id
    r = auth_admin.post(f"/ca/{ca_id}/crl", headers=JSON)
    assert r.status_code == 200 and r.is_json
    assert r.get_json()["id"] == ca_id


# ---- serializers do not leak secrets --------------------------------------

def test_user_json_omits_password_hash(auth_admin):
    users = auth_admin.get("/users/", headers=JSON).get_json()
    assert users
    for u in users:
        assert "password_hash" not in u
        assert {"id", "username", "role"} <= set(u)


def test_ca_detail_json_has_no_key_material(auth_admin):
    auth_admin.post("/ca/create", headers=JSON, data={
        "mode": "generate", "name": "leakcheck", "cn": "Leak Check",
        "key_type": "EC", "key_size": "256", "validity_days": "365",
        "ca_type": "root",
    })
    cas = auth_admin.get("/ca/", headers=JSON).get_json()
    ca_id = next(c["id"] for c in cas if c["name"] == "leakcheck")
    detail = auth_admin.get(f"/ca/{ca_id}", headers=JSON).get_json()
    assert "private_key_enc" not in detail
    assert detail["certificate_pem"].startswith("-----BEGIN CERTIFICATE-----")
