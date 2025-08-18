import os
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from fastapi.testclient import TestClient

from dmv_scam_analysis.api.app import AUTH_SECRET, app, rate_limiter
from dmv_scam_analysis.utils.rate_limiter import RateLimiter


@pytest.mark.security
def test_api_version_header_rejected_when_unsupported():
    client = TestClient(app)
    token = jwt.encode(
        {
            "sub": "u1",
            "exp": datetime.now(UTC) + timedelta(minutes=5),
            "permissions": ["analyze:read", "analyze:write"],
        },
        AUTH_SECRET,
        algorithm="HS256",
    )
    r = client.post(
        "/analyze",
        headers={"Authorization": f"Bearer {token}", "API-Version": "2.0"},
        json={"text": "ok"},
    )
    assert r.status_code == 400
    assert r.json().get("error") == "Unsupported API version"


@pytest.mark.security
def test_file_path_rejection_and_input_sanitization():
    client = TestClient(app)
    token = jwt.encode(
        {
            "sub": "u2",
            "exp": datetime.now(UTC) + timedelta(minutes=5),
            "permissions": ["analyze:read", "analyze:write"],
        },
        AUTH_SECRET,
        algorithm="HS256",
    )

    # Invalid file path
    r1 = client.post(
        "/analyze",
        headers={"Authorization": f"Bearer {token}"},
        json={"text": "x", "file_path": "../../etc/passwd"},
    )
    assert r1.status_code == 400

    # Dangerous text patterns
    for bad in [
        "<script>alert(1)</script>",
        "{{ 7*7 }}",
        "${os.system('ls')}",
        "__proto__",
    ]:
        r2 = client.post(
            "/analyze",
            headers={"Authorization": f"Bearer {token}"},
            json={"text": bad},
        )
        assert r2.status_code == 400

    # SQL/Path injection regex
    r3 = client.post(
        "/analyze",
        headers={"Authorization": f"Bearer {token}"},
        json={"text": "hello; drop table users"},
    )
    assert r3.status_code == 400


@pytest.mark.security
def test_payload_size_thresholds_trigger_errors():
    client = TestClient(app)
    token = jwt.encode(
        {
            "sub": "u3",
            "exp": datetime.now(UTC) + timedelta(minutes=5),
            "permissions": ["analyze:read", "analyze:write"],
        },
        AUTH_SECRET,
        algorithm="HS256",
    )
    # Between 500KB and 2MB -> 400
    text_400 = "a" * (500 * 1024 + 10)
    r_small = client.post(
        "/analyze",
        headers={"Authorization": f"Bearer {token}"},
        json={"text": text_400},
    )
    assert r_small.status_code == 400

    # Above 2MB -> 413
    text_413 = "b" * (2 * 1024 * 1024 + 10)
    r_large = client.post(
        "/analyze",
        headers={"Authorization": f"Bearer {token}"},
        json={"text": text_413},
    )
    assert r_large.status_code == 413


@pytest.mark.security
def test_rate_limit_exceeded_returns_429(monkeypatch):
    client = TestClient(app)
    # Patch global rate_limiter to a strict one
    strict = RateLimiter(max_requests=1, time_window=60)
    monkeypatch.setattr("dmv_scam_analysis.api.app.rate_limiter", strict, raising=True)

    token = jwt.encode(
        {
            "sub": "u4",
            "exp": datetime.now(UTC) + timedelta(minutes=5),
            "permissions": ["analyze:read", "analyze:write"],
        },
        AUTH_SECRET,
        algorithm="HS256",
    )
    headers = {"Authorization": f"Bearer {token}"}

    # First allowed
    r1 = client.post("/analyze", headers=headers, json={"text": "one"})
    # Second should be blocked
    r2 = client.post("/analyze", headers=headers, json={"text": "two"})
    assert r2.status_code == 429


@pytest.mark.security
def test_stats_missing_dates_400():
    client = TestClient(app)
    token = jwt.encode(
        {
            "sub": "u5",
            "exp": datetime.now(UTC) + timedelta(minutes=5),
            "permissions": ["analyze:read"],
        },
        AUTH_SECRET,
        algorithm="HS256",
    )
    r = client.get("/stats", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 400
