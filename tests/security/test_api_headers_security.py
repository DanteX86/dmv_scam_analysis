import pytest
from fastapi.testclient import TestClient

from dmv_scam_analysis.api.app import app


@pytest.mark.security
def test_security_headers_present_on_health():
    client = TestClient(app)
    r = client.get("/health")
    assert r.status_code in (200, 204)
    # Core security headers
    for h in [
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection",
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "Referrer-Policy",
    ]:
        assert h in r.headers


@pytest.mark.security
def test_cors_preflight_has_expected_headers():
    client = TestClient(app)
    r = client.options("/analyze")
    assert r.status_code in (200, 204)
    assert r.headers.get("Access-Control-Allow-Methods")
    assert r.headers.get("Access-Control-Allow-Headers")
