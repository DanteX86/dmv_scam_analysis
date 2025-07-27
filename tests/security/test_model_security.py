"""Security tests for machine learning models and analysis components."""
import pytest
import numpy as np
from tests.utils.test_helpers import (
    generate_test_message,
    create_test_dataset,
    create_test_embeddings
)

def test_model_input_sanitization():
    """Test input sanitization for model predictions."""
    from src.dmv_scam_analysis.core.classifier import ThreatClassifier
    
    classifier = ThreatClassifier()
    
    # Test potentially malicious inputs
    malicious_inputs = [
        # Command injection attempts
        "import os; os.system('rm -rf /')",
        "exec('import socket,subprocess,os;s=socket.socket()')",
        "__import__('os').system('malicious_command')",
        
        # SQL injection attempts
        "'; DROP TABLE users; --",
        "UNION SELECT * FROM secrets",
        
        # File path traversal
        "../../../etc/passwd",
        "..\\..\\windows\\system32\\config",
        
        # XSS attempts
        "<script>alert('xss')</script>",
        "javascript:alert('xss')",
        
        # Template injection
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        
        # Shell injection
        "`rm -rf /`",
        "$(rm -rf /)",
        "&& rm -rf /",
        
        # Null bytes and control characters
        "test\x00message",
        "test\nmalicious\rcommand",
        
        # Unicode exploits
        "test\u202Eevil",
        "test\uff00evil"
    ]
    
    for input_text in malicious_inputs:
        # Model should handle these inputs without executing them
        try:
            result = classifier.predict([input_text])
            assert isinstance(result[0], float)
            assert 0 <= result[0] <= 1
        except Exception as e:
            assert not isinstance(e, (OSError, ImportError, SystemError))

def test_model_output_validation():
    """Test validation of model outputs."""
    from src.dmv_scam_analysis.core.classifier import ThreatClassifier
    from src.dmv_scam_analysis.analysis.behavioral import BehavioralAnalyzer
    
    classifier = ThreatClassifier()
    analyzer = BehavioralAnalyzer()
    
    # Generate test data
    test_messages = create_test_dataset(size=10)
    
    # Test classifier outputs
    predictions = classifier.predict(test_messages['text'].tolist())
    
    # Validate prediction format and ranges
    assert isinstance(predictions, np.ndarray)
    assert predictions.shape[0] == len(test_messages)
    assert np.all((predictions >= 0) & (predictions <= 1))
    
    # Test analyzer outputs
    for _, message in test_messages.iterrows():
        analysis = analyzer.analyze([message.to_dict()])
        
        # Validate analysis structure
        assert isinstance(analysis, dict)
        assert all(key in analysis for key in [
            'threat_score',
            'confidence',
            'indicators',
            'analysis_id'
        ])
        
        # Validate value ranges and types
        assert 0 <= analysis['threat_score'] <= 1
        assert 0 <= analysis['confidence'] <= 1
        assert isinstance(analysis['indicators'], list)
        assert isinstance(analysis['analysis_id'], str)

def test_model_memory_security():
    """Test memory handling in model operations."""
    import psutil
    import os
    
    process = psutil.Process(os.getpid())
    from src.dmv_scam_analysis.core.classifier import ThreatClassifier
    
    # Monitor memory before model load
    memory_before = process.memory_info().rss
    
    # Initialize model
    classifier = ThreatClassifier()
    
    # Monitor memory after model load
    memory_after = process.memory_info().rss
    memory_increase = memory_after - memory_before
    
    # Memory increase should be reasonable
    assert memory_increase < 1024 * 1024 * 500  # Less than 500MB
    
    # Test memory handling with large inputs
    large_input = " ".join(["test"] * 10000)  # Large but not unreasonable
    huge_input = " ".join(["test"] * 1000000)  # Unreasonably large
    
    # Large input should work
    result = classifier.predict([large_input])
    assert isinstance(result[0], float)
    
    # Huge input should either be handled or fail gracefully
    try:
        result = classifier.predict([huge_input])
        assert isinstance(result[0], float)
    except Exception as e:
        assert isinstance(e, (ValueError, MemoryError))

def test_model_timing_attacks():
    """Test protection against timing attacks."""
    from src.dmv_scam_analysis.core.classifier import ThreatClassifier
    import time
    
    classifier = ThreatClassifier()
    
    def measure_prediction_time(input_text):
        start_time = time.time()
        classifier.predict([input_text])
        return time.time() - start_time
    
    # Test timing consistency
    normal_input = "This is a normal message about license renewal"
    malicious_input = "'; DROP TABLE users; --"
    
    normal_times = [measure_prediction_time(normal_input) for _ in range(10)]
    malicious_times = [measure_prediction_time(malicious_input) for _ in range(10)]
    
    # Calculate timing statistics
    avg_normal = np.mean(normal_times)
    avg_malicious = np.mean(malicious_times)
    
    # Timing difference should be minimal
    assert abs(avg_normal - avg_malicious) < 0.1  # Less than 100ms difference

def test_adversarial_input_protection():
    """Test protection against adversarial inputs."""
    from src.dmv_scam_analysis.core.classifier import ThreatClassifier
    
    classifier = ThreatClassifier()
    
    # Test various adversarial techniques
    adversarial_inputs = [
        # Character substitution
        "Urg3nt: Y0ur l1c3ns3 n33ds r3n3w4l",
        # Unicode homoglyphs
        "𝚄𝚁𝙶𝙴𝙽𝚃: 𝚈𝚘𝚞𝚛 𝚕𝚒𝚌𝚎𝚗𝚜𝚎 𝚗𝚎𝚎𝚍𝚜 𝚛𝚎𝚗𝚎𝚠𝚊𝚕",
        # Hidden characters
        "U\u200bR\u200bG\u200bE\u200bN\u200bT",
        # Mixed scripts
        "URԌЕΝТ: Yоur lісеnѕе",
        # Excessive spacing
        "U R G E N T : L i c e n s e",
        # Repetition
        "URGENT" * 100,
        # Random noise
        "".join(chr(np.random.randint(32, 127)) for _ in range(100))
    ]
    
    baseline = classifier.predict(["URGENT: Your license needs renewal"])[0]
    
    for input_text in adversarial_inputs:
        prediction = classifier.predict([input_text])[0]
        
        # Predictions should be reasonably consistent
        assert abs(prediction - baseline) < 0.3

def test_model_versioning_security():
    """Test security of model versioning and updates."""
    import hashlib
    import json
    
    def get_model_hash(model_data):
        """Calculate hash of model data."""
        return hashlib.sha256(json.dumps(model_data, sort_keys=True).encode()).hexdigest()
    
    # Test model configuration
    model_config = {
        "version": "1.0.0",
        "architecture": "transformer",
        "input_size": 768,
        "num_classes": 1,
        "threshold": 0.5
    }
    
    original_hash = get_model_hash(model_config)
    
    # Attempt to tamper with configuration
    tampered_config = model_config.copy()
    tampered_config["threshold"] = 0.1
    tampered_hash = get_model_hash(tampered_config)
    
    # Hashes should be different
    assert original_hash != tampered_hash

def test_embedding_security():
    """Test security of embedding operations."""
    embeddings = create_test_embeddings(num_samples=10)
    
    # Test embedding properties
    assert isinstance(embeddings, np.ndarray)
    assert embeddings.dtype in [np.float32, np.float64]
    assert not np.any(np.isnan(embeddings))
    assert not np.any(np.isinf(embeddings))
    
    # Test embedding normalization
    norms = np.linalg.norm(embeddings, axis=1)
    assert np.allclose(norms, 1.0, rtol=1e-5) or np.all(norms < 100.0)

def test_model_isolation():
    """Test model isolation and resource cleanup."""
    import gc
    from src.dmv_scam_analysis.core.classifier import ThreatClassifier
    
    def create_and_use_model():
        classifier = ThreatClassifier()
        result = classifier.predict(["test message"])
        return result
    
    # Test multiple model instantiations
    initial_memory = psutil.Process().memory_info().rss
    
    for _ in range(10):
        result = create_and_use_model()
        assert isinstance(result[0], float)
    
    # Force garbage collection
    gc.collect()
    
    final_memory = psutil.Process().memory_info().rss
    memory_increase = final_memory - initial_memory
    
    # Memory usage should be stable
    assert memory_increase < 50 * 1024 * 1024  # Less than 50MB increase

def test_confidence_score_security():
    """Test security of confidence score calculations."""
    from src.dmv_scam_analysis.analysis.behavioral import BehavioralAnalyzer
    
    analyzer = BehavioralAnalyzer()
    test_data = create_test_dataset(size=10)
    
    for _, message in test_data.iterrows():
        analysis = analyzer.analyze([message.to_dict()])
        
        # Validate confidence score
        confidence = analysis['confidence']
        assert isinstance(confidence, float)
        assert 0 <= confidence <= 1
        
        # High confidence should correspond to clear indicators
        if confidence > 0.8:
            assert len(analysis['indicators']) >= 2

def test_feature_extraction_security():
    """Test security of feature extraction process."""
    from src.dmv_scam_analysis.core.classifier import ThreatClassifier
    
    classifier = ThreatClassifier()
    
    # Test feature extraction with various inputs
    test_inputs = [
        # Normal input
        "Regular message about license renewal",
        # Very short input
        "a",
        # Very long input
        "test " * 1000,
        # Special characters
        "!@#$%^&*()",
        # Mixed languages
        "English and 日本語 mixed",
        # Empty strings
        "",
        # Whitespace
        "   \n\t   ",
        # Non-printable characters
        "".join(chr(i) for i in range(32))
    ]
    
    for input_text in test_inputs:
        try:
            features = classifier.extract_features([input_text])
            
            # Validate feature properties
            assert isinstance(features, np.ndarray)
            assert not np.any(np.isnan(features))
            assert not np.any(np.isinf(features))
            assert np.all(np.abs(features) < 1e6)  # Reasonable bounds
            
        except Exception as e:
            # Should only raise ValueError for invalid inputs
            assert isinstance(e, ValueError)
