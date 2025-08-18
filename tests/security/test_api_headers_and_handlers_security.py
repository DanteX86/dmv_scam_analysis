from datetime import UTC, datetime, timedelta

import jwt
import pytest
from fastapi.testclient import TestClient

from dmv_scam_analysis.api import app as app_mod
from dmv_scam_analysis.api.app import AUTH_SECRET, app


@pytest.mark.security
def test_health_includes_middleware_headers():
    client = TestClient(app)
    r = client.get("/health")
    assert r.status_code == 200
    # Middleware headers present
    assert "X-Request-ID" in r.headers
    assert "X-Response-Time" in r.headers
    # Security headers too (covered elsewhere but verify here as well)
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"


@pytest.mark.security
def test_analyze_400_handler_payload_and_headers():
    client = TestClient(app)
    token = jwt.encode(
        {
            "sub": "writer",
            "exp": datetime.now(UTC) + timedelta(minutes=5),
            "permissions": ["analyze:write"],
        },
        AUTH_SECRET,
        algorithm="HS256",
    )
    # Trigger input sanitization 400
    r = client.post(
        "/analyze",
        headers={"Authorization": f"Bearer {token}"},
        json={"text": "<script>alert(1)</script>"},
    )
    assert r.status_code == 400
    body = r.json()
    assert body.get("error") == "Invalid input"
    assert isinstance(body.get("timestamp"), str)
    # Headers from middleware should still be present on error response
    assert "X-Request-ID" in r.headers
    assert "X-Response-Time" in r.headers


@pytest.mark.security
def test_analyze_413_handler_payload_and_headers():
    client = TestClient(app)
    token = jwt.encode(
        {
            "sub": "writer2",
            "exp": datetime.now(UTC) + timedelta(minutes=5),
            "permissions": ["analyze:write"],
        },
        AUTH_SECRET,
        algorithm="HS256",
    )
    # Trigger 413
    huge = "x" * (2 * 1024 * 1024 + 100)
    r = client.post(
        "/analyze",
        headers={"Authorization": f"Bearer {token}"},
        json={"text": huge},
    )
    assert r.status_code == 413
    body = r.json()
    assert body.get("error") == "Request payload too large"
    assert isinstance(body.get("timestamp"), str)
    assert "X-Request-ID" in r.headers
    assert "X-Response-Time" in r.headers


@pytest.mark.security
def test_stats_500_handler_payload(monkeypatch):
    client = TestClient(app)

    # Ensure rate limiter won't block
    from dmv_scam_analysis.utils.rate_limiter import RateLimiter

    monkeypatch.setattr(
        app_mod,
        "rate_limiter",
        RateLimiter(max_requests=1000, time_window=1),
        raising=True,
    )

    # Patch analyzer.get_statistics to raise to hit 500 path
    class Broken:
        def get_statistics(self, start_date, end_date):
            raise RuntimeError("fail")

    monkeypatch.setattr(app_mod, "analyzer", Broken(), raising=True)

    token = jwt.encode(
        {
            "sub": "reader",
            "exp": datetime.now(UTC) + timedelta(minutes=5),
            "permissions": ["analyze:read"],
        },
        AUTH_SECRET,
        algorithm="HS256",
    )
    params = {"start_date": "2025-01-01T00:00:00", "end_date": "2025-01-02T00:00:00"}
    r = client.get(
        "/stats", headers={"Authorization": f"Bearer {token}"}, params=params
    )
    assert r.status_code == 500
    body = r.json()
    assert body.get("error") == "Failed to get statistics"
    assert isinstance(body.get("timestamp"), str)
