import pytest
from fastapi.testclient import TestClient

from dmv_scam_analysis.api.app import app


@pytest.mark.security
def test_auth_missing_header_returns_401():
    client = TestClient(app)
    r = client.post("/analyze", json={"text": "x"})
    assert r.status_code == 401
    assert r.json().get("error") == "Not authenticated"


@pytest.mark.security
def test_auth_invalid_scheme_returns_401():
    client = TestClient(app)
    r = client.post(
        "/analyze", headers={"Authorization": "Basic abc"}, json={"text": "x"}
    )
    assert r.status_code == 401
    assert r.json().get("error") == "Invalid authentication scheme"


@pytest.mark.security
def test_auth_empty_token_returns_401():
    client = TestClient(app)
    r = client.post(
        "/analyze", headers={"Authorization": "Bearer    "}, json={"text": "x"}
    )
    assert r.status_code == 401
    assert r.json().get("error") == "Invalid token format"
