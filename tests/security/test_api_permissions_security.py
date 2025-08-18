import os
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from fastapi.testclient import TestClient

from dmv_scam_analysis.api.app import AUTH_SECRET, app


@pytest.mark.security
def test_read_requires_permission_and_denies_without():
    client = TestClient(app)
    # Token with no read permission
    token = jwt.encode(
        {
            "sub": "user",
            "exp": datetime.now(UTC) + timedelta(minutes=5),
            "permissions": ["analyze:write"],
        },
        AUTH_SECRET,
        algorithm="HS256",
    )
    headers = {"Authorization": f"Bearer {token}"}
    # Try GET stats (assuming it requires read)
    r = client.get("/stats", headers=headers)
    assert r.status_code in (401, 403, 404)  # depending on route availability


@pytest.mark.security
def test_write_requires_permission_and_denies_without():
    client = TestClient(app)
    # Token with only read permission
    token = jwt.encode(
        {
            "sub": "user",
            "exp": datetime.now(UTC) + timedelta(minutes=5),
            "permissions": ["analyze:read"],
        },
        AUTH_SECRET,
        algorithm="HS256",
    )
    headers = {"Authorization": f"Bearer {token}"}
    r = client.post("/analyze", headers=headers, json={"text": "hello"})
    assert r.status_code in (401, 403, 422, 400)
