"""Test helper utilities."""
import json
import pandas as pd
import numpy as np
from typing import Dict, List, Any, Union
from pathlib import Path

def generate_test_message(
    text: str = None,
    source: str = None,
    metadata: Dict[str, Any] = None
) -> Dict[str, Any]:
    """Generate a test message with default values."""
    if text is None:
        text = "URGENT: Your driver's license needs renewal"
    if source is None:
        source = "email"
    if metadata is None:
        metadata = {
            "sender": "test@example.com",
            "subject": "Test Message",
            "timestamp": "2025-06-27T12:00:00Z"
        }
    
    return {
        "text": text,
        "source": source,
        "metadata": metadata
    }

def create_test_dataset(
    size: int = 100,
    scam_ratio: float = 0.5,
    random_seed: int = 42
) -> pd.DataFrame:
    """Create a synthetic dataset for testing."""
    np.random.seed(random_seed)
    
    # Generate scam and non-scam messages
    scam_count = int(size * scam_ratio)
    non_scam_count = size - scam_count
    
    scam_templates = [
        "URGENT: Your license will be suspended. Pay ${} now",
        "DMV Alert: Your registration needs renewal. Click {}",
        "Final Warning: License expiration. Visit {}",
    ]
    
    non_scam_templates = [
        "Your license renewal is due on {}",
        "DMV: Schedule your test for {}",
        "Registration reminder for {}",
    ]
    
    def generate_random_message(is_scam: bool) -> Dict[str, Any]:
        templates = scam_templates if is_scam else non_scam_templates
        template = np.random.choice(templates)
        
        if is_scam:
            value = f"${np.random.randint(50, 500)}"
            url = f"http://scam-{np.random.randint(1000, 9999)}.com"
            text = template.format(value if "{}" in template else url)
        else:
            date = pd.Timestamp.now() + pd.Timedelta(days=np.random.randint(1, 90))
            text = template.format(date.strftime("%Y-%m-%d"))
        
        return {
            "text": text,
            "is_scam": is_scam,
            "confidence": np.random.uniform(0.7, 1.0),
            "source": np.random.choice(["email", "sms", "web"]),
            "timestamp": pd.Timestamp.now().isoformat()
        }
    
    data = (
        [generate_random_message(True) for _ in range(scam_count)] +
        [generate_random_message(False) for _ in range(non_scam_count)]
    )
    
    return pd.DataFrame(data)

def compare_model_outputs(
    actual: Union[np.ndarray, List],
    expected: Union[np.ndarray, List],
    tolerance: float = 1e-6
) -> bool:
    """Compare model outputs with tolerance."""
    actual = np.array(actual)
    expected = np.array(expected)
    
    if actual.shape != expected.shape:
        return False
    
    return np.allclose(actual, expected, rtol=tolerance)

def load_test_data(file_path: Union[str, Path]) -> Dict[str, Any]:
    """Load test data from a file."""
    file_path = Path(file_path)
    
    if not file_path.exists():
        raise FileNotFoundError(f"Test data file not found: {file_path}")
    
    if file_path.suffix == ".json":
        with open(file_path) as f:
            return json.load(f)
    elif file_path.suffix == ".csv":
        return pd.read_csv(file_path).to_dict(orient="records")
    else:
        raise ValueError(f"Unsupported file format: {file_path.suffix}")

def validate_model_prediction(
    prediction: Dict[str, Any],
    expected_keys: List[str] = None
) -> bool:
    """Validate model prediction format and values."""
    if expected_keys is None:
        expected_keys = [
            "threat_score",
            "confidence",
            "categories",
            "indicators"
        ]
    
    # Check required keys
    if not all(key in prediction for key in expected_keys):
        return False
    
    # Validate threat score
    if not 0 <= prediction["threat_score"] <= 1:
        return False
    
    # Validate confidence
    if not 0 <= prediction["confidence"] <= 1:
        return False
    
    # Validate categories
    if not isinstance(prediction["categories"], list):
        return False
    
    # Validate indicators
    if not isinstance(prediction["indicators"], list):
        return False
    
    return True

def create_test_embeddings(
    num_samples: int = 100,
    embedding_dim: int = 768,
    random_seed: int = 42
) -> np.ndarray:
    """Create test embeddings for model evaluation."""
    np.random.seed(random_seed)
    return np.random.randn(num_samples, embedding_dim)

def create_test_features(
    num_samples: int = 100,
    num_features: int = 10,
    random_seed: int = 42
) -> pd.DataFrame:
    """Create test features for model training."""
    np.random.seed(random_seed)
    
    features = {
        "text_length": np.random.randint(10, 1000, num_samples),
        "has_url": np.random.choice([0, 1], num_samples),
        "has_phone": np.random.choice([0, 1], num_samples),
        "has_email": np.random.choice([0, 1], num_samples),
        "urgency_score": np.random.uniform(0, 1, num_samples),
        "spelling_errors": np.random.randint(0, 10, num_samples),
        "capitalization_ratio": np.random.uniform(0, 1, num_samples),
        "punctuation_ratio": np.random.uniform(0, 1, num_samples),
        "sentiment_score": np.random.uniform(-1, 1, num_samples),
        "complexity_score": np.random.uniform(0, 1, num_samples)
    }
    
    return pd.DataFrame(features)
