"""Security tests for the API endpoints and authentication."""
import pytest
import jwt
import time
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from dmv_scam_analysis.api.app import app
from dmv_scam_analysis.utils.test_helpers import generate_test_message
import base64
import json
import secrets

@pytest.fixture
def test_client():
    """Create test client."""
    return TestClient(app)

@pytest.fixture
def valid_token():
    """Generate a valid JWT token for testing."""
    secret = "test_secret"  # In production, use secure env vars
    payload = {
        "sub": "test_user",
        "exp": datetime.utcnow() + timedelta(hours=1),
        "permissions": ["analyze:read", "analyze:write"]
    }
    return jwt.encode(payload, secret, algorithm="HS256")

def test_missing_auth_header(test_client):
    """Test endpoints reject requests without auth header."""
    endpoints = [
        ("/analyze", "POST", {}),
        ("/stats", "GET", {}),
    ]
    
    for path, method, data in endpoints:
        if method == "GET":
            response = test_client.get(path)
        else:
            response = test_client.post(path, json=data)
        
        assert response.status_code == 401
        assert "Not authenticated" in response.json()["error"]

def test_invalid_auth_scheme(test_client):
    """Test rejection of invalid auth schemes."""
    headers = {"Authorization": "Basic YWRtaW46cGFzc3dvcmQ="}
    response = test_client.post("/analyze", headers=headers, json={})
    
    assert response.status_code == 401
    assert "Invalid authentication scheme" in response.json()["error"]

def test_invalid_token_format(test_client):
    """Test rejection of malformed tokens."""
    invalid_tokens = [
        "not_a_jwt_token",
        "Bearer ",
        "Bearer invalid.token.format",
        "Bearer " + base64.b64encode(b"invalid").decode()
    ]
    
    for token in invalid_tokens:
        headers = {"Authorization": token}
        response = test_client.post("/analyze", headers=headers, json={})
        
        assert response.status_code == 401
        assert "Invalid token format" in response.json()["error"]

def test_expired_token(test_client):
    """Test rejection of expired tokens."""
    secret = "test_secret"
    payload = {
        "sub": "test_user",
        "exp": datetime.utcnow() - timedelta(hours=1)
    }
    expired_token = jwt.encode(payload, secret, algorithm="HS256")
    
    headers = {"Authorization": f"Bearer {expired_token}"}
    response = test_client.post("/analyze", headers=headers, json={})
    
    assert response.status_code == 401
    assert "Token has expired" in response.json()["error"]

def test_token_permissions(test_client, valid_token):
    """Test token permission enforcement."""
    # Token with read-only permission
    read_token = jwt.encode({
        "sub": "test_user",
        "exp": datetime.utcnow() + timedelta(hours=1),
        "permissions": ["analyze:read"]
    }, "test_secret", algorithm="HS256")
    
    # Try to write with read-only token
    headers = {"Authorization": f"Bearer {read_token}"}
    response = test_client.post("/analyze", headers=headers, json={})
    
    assert response.status_code == 403
    assert "Insufficient permissions" in response.json()["error"]

def test_input_validation(test_client, valid_token):
    """Test input validation and sanitization."""
    headers = {"Authorization": f"Bearer {valid_token}"}
    
    # Test SQL injection attempt
    malicious_inputs = [
        {"text": "'; DROP TABLE users; --"},
        {"text": "UNION SELECT * FROM secrets"},
        {"text": "<script>alert('xss')</script>"},
        {"text": "${HOME:-.}/etc/passwd"},
        {"text": "../../etc/passwd"},
        {"text": "%(python)s"},
        {"text": "{..__class__}"}
    ]
    
    for input_data in malicious_inputs:
        response = test_client.post(
            "/analyze",
            headers=headers,
            json=input_data
        )
        assert response.status_code in [400, 422]

def test_rate_limiting(test_client, valid_token):
    """Test rate limiting enforcement."""
    headers = {"Authorization": f"Bearer {valid_token}"}
    
    # Make requests up to limit
    for _ in range(100):  # Assuming limit is 100 requests/minute
        response = test_client.post(
            "/analyze",
            headers=headers,
            json=generate_test_message()
        )
        assert response.status_code == 200
    
    # Next request should be rate limited
    response = test_client.post(
        "/analyze",
        headers=headers,
        json=generate_test_message()
    )
    assert response.status_code == 429
    assert "Rate limit exceeded" in response.json()["error"]

def test_sensitive_data_exposure(test_client, valid_token):
    """Test prevention of sensitive data exposure."""
    headers = {"Authorization": f"Bearer {valid_token}"}
    
    # Trigger an error that might expose sensitive data
    response = test_client.post(
        "/analyze",
        headers=headers,
        json={"text": "a" * 1000000}  # Very large input
    )
    
    assert response.status_code == 400
    response_data = response.json()
    
    # Check that error response doesn't contain sensitive information
    assert "stacktrace" not in response_data
    assert "server_error" not in response_data
    assert "debug" not in response_data
    assert not any(key.startswith("_") for key in response_data.keys())

def test_cors_configuration(test_client):
    """Test CORS configuration."""
    headers = {
        "Origin": "https://malicious-site.com",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "Authorization,Content-Type"
    }
    
    # Preflight request
    response = test_client.options(
        "/analyze",
        headers=headers
    )
    
    # Check CORS headers
    assert "Access-Control-Allow-Origin" in response.headers
    assert response.headers["Access-Control-Allow-Origin"] != "*"
    assert "https://malicious-site.com" not in response.headers["Access-Control-Allow-Origin"]

def test_http_security_headers(test_client, valid_token):
    """Test security-related HTTP headers."""
    _headers = {"Authorization": f"Bearer {valid_token}"}
    response = test_client.get("/health")
    
    security_headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "Referrer-Policy": "strict-origin-when-cross-origin"
    }
    
    for header, expected_value in security_headers.items():
        assert response.headers.get(header) == expected_value

def test_brute_force_protection(test_client):
    """Test protection against brute force attacks."""
    # Try multiple invalid tokens
    attempts = 0
    start_time = time.time()
    
    while attempts < 50 and time.time() - start_time < 60:
        token = secrets.token_hex(32)
        headers = {"Authorization": f"Bearer {token}"}
        
        response = test_client.post(
            "/analyze",
            headers=headers,
            json=generate_test_message()
        )
        
        attempts += 1
        
        if response.status_code == 429:
            # Successfully detected and blocked brute force attempt
            break
        
        time.sleep(0.1)  # Avoid overwhelming the server
    
    assert response.status_code == 429
    assert "Too many failed attempts" in response.json()["error"]

def test_json_injection(test_client, valid_token):
    """Test protection against JSON injection attacks."""
    headers = {"Authorization": f"Bearer {valid_token}"}
    
    # Test various JSON injection payloads
    payloads = [
        {"text": json.dumps({"__proto__": {"admin": True}})},
        {"text": json.dumps({"constructor": {"prototype": {"admin": True}}})},
        {"text": json.dumps({"text": None, "__proto__": []})},
        {"text": "{{constructor.constructor('return this')()}}"}
    ]
    
    for payload in payloads:
        response = test_client.post(
            "/analyze",
            headers=headers,
            json=payload
        )
        assert response.status_code in [400, 422]

def test_secure_file_operations(test_client, valid_token):
    """Test security of file operations."""
    headers = {"Authorization": f"Bearer {valid_token}"}
    
    # Test path traversal attempts
    suspicious_paths = [
        "../../../etc/passwd",
        "..\\..\\windows\\system32\\config",
        "/etc/shadow",
        "C:\\boot.ini",
        "file:///etc/passwd",
        "....//....//etc/passwd"
    ]
    
    for path in suspicious_paths:
        response = test_client.post(
            "/analyze",
            headers=headers,
            json={"file_path": path}
        )
        assert response.status_code in [400, 422]

def test_memory_limits(test_client, valid_token):
    """Test memory usage limits and protection."""
    headers = {"Authorization": f"Bearer {valid_token}"}
    
    # Try to send a very large payload
    large_data = {
        "text": "a" * (10 * 1024 * 1024)  # 10MB of data
    }
    
    response = test_client.post(
        "/analyze",
        headers=headers,
        json=large_data
    )
    
    assert response.status_code == 413  # Request Entity Too Large

def test_regex_dos_protection(test_client, valid_token):
    """Test protection against ReDoS attacks."""
    headers = {"Authorization": f"Bearer {valid_token}"}
    
    # Malicious regex patterns that could cause catastrophic backtracking
    patterns = [
        "a" * 100000 + "!",
        "(a+)+" * 100,
        "(a|a|a|a)" * 100,
        "([a-zA-Z]+)*"
    ]
    
    for pattern in patterns:
        response = test_client.post(
            "/analyze",
            headers=headers,
            json={"text": pattern}
        )
        
        # Should either reject the pattern or process it within a reasonable time
        assert response.elapsed.total_seconds() < 1.0

def test_api_versioning(test_client, valid_token):
    """Test API versioning security."""
    headers = {
        "Authorization": f"Bearer {valid_token}",
        "Accept": "application/json"
    }
    
    # Test API version header
    versioned_headers = headers.copy()
    versioned_headers["API-Version"] = "999.0"
    
    response = test_client.post(
        "/analyze",
        headers=versioned_headers,
        json=generate_test_message()
    )
    
    assert response.status_code == 400
    assert "Unsupported API version" in response.json()["error"]
