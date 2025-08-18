import logging
import os
import sys
from pathlib import Path

import jwt
import pytest
from fastapi.testclient import TestClient

from dmv_scam_analysis.api.app import app, AUTH_SECRET, analyzer


def _make_token(sub="unit", perms=("analyze:read",)):
    payload = {"sub": sub, "permissions": list(perms)}
    return jwt.encode(payload, AUTH_SECRET, algorithm="HS256")


def test_stats_raises_500_on_backend_error(monkeypatch):
    client = TestClient(app)

    # Monkeypatch analyzer.get_statistics to raise
    def boom(*args, **kwargs):
        raise RuntimeError("backend failed")

    monkeypatch.setattr(analyzer, "get_statistics", boom)

    token = _make_token(perms=("analyze:read",))
    headers = {"Authorization": f"Bearer {token}"}

    # Provide required query params
    resp = client.get(
        "/stats",
        headers=headers,
        params={"start_date": "2025-01-01T00:00:00Z", "end_date": "2025-01-02T00:00:00Z"},
    )
    assert resp.status_code == 500
    assert "Failed to get statistics" in resp.json().get("error", "")


def test_api_version_header_invalid_returns_400():
    client = TestClient(app)
    token = _make_token(perms=("analyze:write",))
    headers = {"Authorization": f"Bearer {token}", "API-Version": "99.9"}
    resp = client.post("/analyze", headers=headers, json={"text": "hello"})
    assert resp.status_code == 400
    assert "Unsupported API version" in resp.json().get("error", "")

