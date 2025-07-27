"""Integration tests for data pipeline."""
import pytest
from dmv_scam_analysis.utils.validation import DataValidator
from dmv_scam_analysis.analysis.sentiment import SentimentAnalyzer as NLPAnalyzer
from dmv_scam_analysis.core.classifier import MLThreatClassifier as ThreatClassifier

@pytest.fixture
def sample_data():
    """Create sample data for testing."""
    return {
        "messages": [
            {
                "text": "Your driver's license needs renewal. Click here: http://suspicious-link.com",
                "source": "email",
                "timestamp": "2025-06-27T12:00:00Z"
            },
            {
                "text": "DMV notification: Pay $299 to update your license",
                "source": "sms",
                "timestamp": "2025-06-27T12:30:00Z"
            }
        ]
    }

@pytest.fixture
def pipeline_components():
    """Initialize pipeline components."""
    return {
        "preprocessor": DataPreprocessor(),
        "validator": DataValidator(),
        "nlp_analyzer": NLPAnalyzer(),
        "classifier": ThreatClassifier()
    }

def test_end_to_end_pipeline(sample_data, pipeline_components):
    """Test complete data processing pipeline."""
    # Preprocess data
    preprocessed_data = pipeline_components["preprocessor"].process(sample_data["messages"])
    assert len(preprocessed_data) == len(sample_data["messages"])
    
    # Validate data
    validation_result = pipeline_components["validator"].validate(preprocessed_data)
    assert validation_result.is_valid
    
    # Analyze text
    nlp_results = pipeline_components["nlp_analyzer"].analyze(preprocessed_data)
    assert "entities" in nlp_results
    assert "sentiment" in nlp_results
    
    # Classify threats
    threat_scores = pipeline_components["classifier"].predict(preprocessed_data)
    assert len(threat_scores) == len(sample_data["messages"])
    assert all(0 <= score <= 1 for score in threat_scores)

def test_pipeline_error_handling(pipeline_components):
    """Test pipeline error handling with invalid input."""
    invalid_data = [{"text": "", "source": "unknown"}]
    
    # Test preprocessing error handling
    with pytest.raises(ValueError):
        pipeline_components["preprocessor"].process(invalid_data)
    
    # Test validation error handling
    validation_result = pipeline_components["validator"].validate(invalid_data)
    assert not validation_result.is_valid
    
    # Test NLP analysis error handling
    with pytest.raises(ValueError):
        pipeline_components["nlp_analyzer"].analyze(invalid_data)
    
    # Test classification error handling
    with pytest.raises(ValueError):
        pipeline_components["classifier"].predict(invalid_data)

def test_pipeline_performance(sample_data, pipeline_components):
    """Test pipeline performance metrics."""
    import time
    
    start_time = time.time()
    
    # Process multiple times to get average performance
    for _ in range(10):
        preprocessed = pipeline_components["preprocessor"].process(sample_data["messages"])
        _ = pipeline_components["validator"].validate(preprocessed)
        _ = pipeline_components["nlp_analyzer"].analyze(preprocessed)
        _ = pipeline_components["classifier"].predict(preprocessed)
    
    total_time = time.time() - start_time
    assert total_time / 10 < 1.0  # Average processing time should be less than 1 second
