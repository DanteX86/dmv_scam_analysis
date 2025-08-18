from datetime import UTC, datetime, timedelta

import jwt
import pytest
from fastapi import HTTPException
from fastapi.requests import Request
from fastapi.testclient import TestClient

from dmv_scam_analysis.api import app as app_mod
from dmv_scam_analysis.api.app import (
    _GLOBAL_FAILED,
    AUTH_SECRET,
    FAILED_ATTEMPTS,
    app,
    general_exception_handler,
    http_exception_handler,
)
from dmv_scam_analysis.utils.rate_limiter import RateLimiter


@pytest.mark.security
def test_expired_token_hits_429_after_local_limit(monkeypatch):
    client = TestClient(app)

    # Reduce limits for fast triggering
    monkeypatch.setattr(app_mod, "FAILED_ATTEMPT_LIMIT", 2, raising=True)
    monkeypatch.setattr(app_mod, "FAILED_ATTEMPT_WINDOW", 60, raising=True)
    # Reset per-token window
    FAILED_ATTEMPTS.clear()

    expired = jwt.encode(
        {
            "sub": "userA",
            "exp": datetime.now(UTC) - timedelta(minutes=1),
            "permissions": ["analyze:read"],
        },
        AUTH_SECRET,
        algorithm="HS256",
    )
    headers = {"Authorization": f"Bearer {expired}"}

    r1 = client.post("/analyze", headers=headers, json={})
    r2 = client.post("/analyze", headers=headers, json={})
    r3 = client.post("/analyze", headers=headers, json={})

    # After exceeding local limit, should be 429
    assert r3.status_code == 429


@pytest.mark.security
def test_global_failed_attempts_hits_429(monkeypatch):
    client = TestClient(app)

    # Reduce global limit
    monkeypatch.setattr(app_mod, "_GLOBAL_FAILED_LIMIT", 2, raising=True)
    monkeypatch.setattr(app_mod, "FAILED_ATTEMPT_WINDOW", 60, raising=True)
    # Reset global
    _GLOBAL_FAILED.clear()

    # Use malformed tokens to count as failed attempts
    h = {"Authorization": "Bearer not.a.jwt"}
    r1 = client.post("/analyze", headers=h, json={})
    r2 = client.post("/analyze", headers=h, json={})
    r3 = client.post("/analyze", headers=h, json={})

    assert r3.status_code == 429


@pytest.mark.security
def test_perf_token_bypasses_rate_limit(monkeypatch):
    client = TestClient(app)

    strict = RateLimiter(max_requests=1, time_window=60)
    monkeypatch.setattr(app_mod, "rate_limiter", strict, raising=True)

    headers = {"Authorization": "Bearer test_performance_token"}

    r1 = client.post("/analyze", headers=headers, json={"text": "one"})
    r2 = client.post("/analyze", headers=headers, json={"text": "two"})

    # Both should not be rate-limited (could be 200/400 depending on pipeline, but not 429)
    assert r1.status_code in (200, 400)
    assert r2.status_code in (200, 400)


@pytest.mark.security
def test_http_exception_handler_response():
    # Build a minimal ASGI scope for Request
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/x",
        "headers": [],
    }
    req = Request(scope)
    exc = HTTPException(status_code=401, detail="Not authenticated")

    import anyio

    async def _call():
        return await app_mod.http_exception_handler(req, exc)

    res = anyio.run(_call)
    assert res.status_code == 401
    body = res.body.decode()
    assert "Not authenticated" in body


@pytest.mark.security
def test_general_exception_handler_response():
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/x",
        "headers": [],
    }
    req = Request(scope)

    import anyio

    async def _call():
        return await general_exception_handler(req, Exception("boom"))

    res = anyio.run(_call)
    assert res.status_code == 500
    body = res.body.decode()
    assert "Internal server error" in body
