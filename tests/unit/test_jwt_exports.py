import base64
import csv
import io
import json
from datetime import datetime, timedelta, timezone

import jwt
import pytest
import yaml


@pytest.mark.unit
class TestJWTExports:
    def test_jwt_encode_decode_roundtrip(self):
        # Build a payload using current UTC to avoid expiry while testing
        now = datetime.now(timezone.utc)
        payload = {
            "sub": "user-123",
            "role": "analyst",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
            "scopes": ["read", "analyze"],
        }

        secret = "test-secret"
        token = jwt.encode(payload, secret, algorithm="HS256")

        # PyJWT>=2 returns str; ensure non-empty
        assert isinstance(token, str) and token.count(".") == 2

        decoded = jwt.decode(token, secret, algorithms=["HS256"])
        # exp/iat will be ints; compare selective keys
        for k in ("sub", "role", "iat", "exp", "scopes"):
            assert decoded[k] == payload[k]

    def test_export_import_yaml(self):
        data = {
            "token": jwt.encode({"a": 1}, "s", algorithm="HS256"),
            "meta": {"format": "jwt", "alg": "HS256"},
        }

        # Export to YAML string
        ytext = yaml.safe_dump(data, sort_keys=True)
        assert isinstance(ytext, str) and "token:" in ytext and "meta:" in ytext

        # Import back and round-trip
        loaded = yaml.safe_load(ytext)
        assert loaded == data

        # Validate token decodes
        decoded = jwt.decode(loaded["token"], "s", algorithms=["HS256"])
        assert decoded["a"] == 1

    def test_export_import_csv(self):
        # Example rows for CSV export: id, token
        rows = [
            {"id": "r1", "token": jwt.encode({"i": 1}, "s", algorithm="HS256")},
            {"id": "r2", "token": jwt.encode({"i": 2}, "s", algorithm="HS256")},
        ]

        # Export to CSV in-memory
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=["id", "token"])
        writer.writeheader()
        writer.writerows(rows)
        csv_text = buf.getvalue()
        assert csv_text.splitlines()[0] == "id,token"
        assert "r1" in csv_text and "r2" in csv_text

        # Import back from CSV
        buf2 = io.StringIO(csv_text)
        reader = csv.DictReader(buf2)
        loaded = list(reader)
        assert len(loaded) == 2
        # Ensure tokens are intact and decodable
        for rec in loaded:
            payload = jwt.decode(rec["token"], "s", algorithms=["HS256"])
            assert payload["i"] in (1, 2)
