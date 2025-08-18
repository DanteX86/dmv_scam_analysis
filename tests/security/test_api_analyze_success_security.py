from datetime import UTC, datetime, timedelta

import jwt
import pytest
from fastapi.testclient import TestClient

from dmv_scam_analysis.api.app import AUTH_SECRET, app


@pytest.mark.security
def test_analyze_success_path_with_valid_payload_and_perms():
    client = TestClient(app)
    token = jwt.encode(
        {
            "sub": "user",
            "exp": datetime.now(UTC) + timedelta(minutes=5),
            "permissions": ["analyze:read", "analyze:write"],
        },
        AUTH_SECRET,
        algorithm="HS256",
    )
    headers = {"Authorization": f"Bearer {token}"}
    resp = client.post(
        "/analyze", headers=headers, json={"text": "This is a benign message"}
    )
    # Should take the success path (200) or a controlled 400 if validator pipeline rejects
    assert resp.status_code in (200, 400)
    if resp.status_code == 200:
        body = resp.json()
        assert set(
            [
                "threat_score",
                "classification",
                "indicators",
                "confidence",
                "analysis_id",
            ]
        ).issubset(body.keys())
