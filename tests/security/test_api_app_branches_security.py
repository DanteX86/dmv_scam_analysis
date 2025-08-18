from datetime import UTC, datetime, timedelta

import jwt
import pytest
from fastapi.testclient import TestClient

from dmv_scam_analysis.api import app as app_mod
from dmv_scam_analysis.api.app import AUTH_SECRET, app


@pytest.mark.security
def test_analyze_error_branch_on_classifier_exception(monkeypatch):
    client = TestClient(app)

    # Patch classifier.predict to raise
    class Boom:
        def predict(self, X):
            raise RuntimeError("boom")

    monkeypatch.setattr(app_mod, "classifier", Boom(), raising=True)

    token = jwt.encode(
        {
            "sub": "writer",
            "exp": datetime.now(UTC) + timedelta(minutes=5),
            "permissions": ["analyze:write"],
        },
        AUTH_SECRET,
        algorithm="HS256",
    )
    r = client.post(
        "/analyze", headers={"Authorization": f"Bearer {token}"}, json={"text": "ok"}
    )
    assert r.status_code == 400
    assert r.json().get("error") == "Invalid input"


@pytest.mark.security
def test_analyze_error_branch_on_analyzer_exception(monkeypatch):
    client = TestClient(app)

    class Passthrough:
        def predict(self, X):
            return [0.5]

    class Explode:
        def analyze(self, X):
            raise ValueError("analysis failed")

    monkeypatch.setattr(app_mod, "classifier", Passthrough(), raising=True)
    monkeypatch.setattr(app_mod, "analyzer", Explode(), raising=True)

    token = jwt.encode(
        {
            "sub": "writer2",
            "exp": datetime.now(UTC) + timedelta(minutes=5),
            "permissions": ["analyze:write"],
        },
        AUTH_SECRET,
        algorithm="HS256",
    )
    r = client.post(
        "/analyze", headers={"Authorization": f"Bearer {token}"}, json={"text": "ok"}
    )
    assert r.status_code == 400
    assert r.json().get("error") == "Invalid input"


@pytest.mark.security
def test_stats_rate_limit_branch_returns_429(monkeypatch):
    client = TestClient(app)

    # Use a strict limiter and a token without perf bypass
    from dmv_scam_analysis.utils.rate_limiter import RateLimiter

    strict = RateLimiter(max_requests=1, time_window=60)
    monkeypatch.setattr(app_mod, "rate_limiter", strict, raising=True)

    token = jwt.encode(
        {
            "sub": "reader",
            "exp": datetime.now(UTC) + timedelta(minutes=5),
            "permissions": ["analyze:read"],
        },
        AUTH_SECRET,
        algorithm="HS256",
    )

    params = {
        "start_date": "2025-01-01T00:00:00",
        "end_date": "2025-01-02T00:00:00",
    }

    # First call allowed (though analyzer.get_statistics may fail; it is inside try/except returning 500)
    # We only need to consume the limiter slot; ignore status
    client.get("/stats", headers={"Authorization": f"Bearer {token}"}, params=params)

    # Second call should hit limiter path
    r2 = client.get(
        "/stats", headers={"Authorization": f"Bearer {token}"}, params=params
    )
    assert r2.status_code == 429
