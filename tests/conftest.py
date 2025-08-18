"""Pytest configuration and fixtures."""
import os
import sys
import tempfile
import pytest
import numpy as np
from pathlib import Path
from typing import Dict, List, Any

# Add src directory to Python path for importing modules
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

@pytest.fixture(scope="session")
def test_data_dir():
    """Create a temporary directory for test data."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)

@pytest.fixture(scope="session")
def sample_scam_messages() -> List[Dict[str, Any]]:
    """Generate sample scam messages for testing."""
    return [
        {
            "id": "msg001",
            "text": "URGENT: Your driver's license will be suspended. Pay $200 now.",
            "source": "email",
            "timestamp": "2025-06-27T10:00:00Z",
            "metadata": {
                "sender": "fake-dmv@scammer.com",
                "subject": "License Suspension Notice",
                "ip_address": "192.168.1.100"
            }
        },
        {
            "id": "msg002",
            "text": "DMV Alert: Click here to verify your license status",
            "source": "sms",
            "timestamp": "2025-06-27T11:00:00Z",
            "metadata": {
                "sender": "+1234567890",
                "carrier": "Unknown"
            }
        }
    ]

@pytest.fixture(scope="session")
def sample_model_features() -> np.ndarray:
    """Generate sample features for model testing."""
    return np.random.rand(100, 10)

@pytest.fixture(scope="session")
def sample_model_labels() -> np.ndarray:
    """Generate sample labels for model testing."""
    return np.random.randint(0, 2, 100)

@pytest.fixture(scope="session")
def mock_config():
    """Create mock configuration for testing."""
    return {
        "model": {
            "type": "transformer",
            "params": {
                "max_length": 512,
                "num_heads": 8,
                "num_layers": 6
            }
        },
        "training": {
            "batch_size": 32,
            "epochs": 10,
            "learning_rate": 1e-4
        },
        "data": {
            "train_split": 0.8,
            "val_split": 0.1,
            "test_split": 0.1
        }
    }

@pytest.fixture(scope="function")
def mock_database():
    """Create a temporary database for testing."""
    db_path = tempfile.mktemp(suffix=".db")
    
    # Create test tables
    import sqlite3
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    # Create messages table
    c.execute('''
        CREATE TABLE messages (
            id TEXT PRIMARY KEY,
            text TEXT,
            source TEXT,
            timestamp TEXT,
            metadata TEXT
        )
    ''')
    
    # Create analysis results table
    c.execute('''
        CREATE TABLE analysis_results (
            message_id TEXT,
            threat_score REAL,
            analysis_timestamp TEXT,
            model_version TEXT,
            FOREIGN KEY(message_id) REFERENCES messages(id)
        )
    ''')
    
    conn.commit()
    conn.close()
    
    yield db_path
    
    # Cleanup
    if os.path.exists(db_path):
        os.remove(db_path)

@pytest.fixture(scope="session")
def mock_api_responses():
    """Mock API responses for testing."""
    return {
        "threat_analysis": {
            "status": "success",
            "data": {
                "threat_score": 0.85,
                "confidence": 0.92,
                "categories": ["phishing", "financial"],
                "indicators": ["urgency", "payment", "threat"]
            }
        },
        "entity_extraction": {
            "status": "success",
            "data": {
                "entities": [
                    {"type": "MONEY", "text": "$200", "start": 45, "end": 49},
                    {"type": "ORG", "text": "DMV", "start": 0, "end": 3}
                ]
            }
        }
    }

@pytest.fixture(scope="session")
def test_metrics():
    """Define test metrics and thresholds."""
    return {
        "accuracy": 0.95,
        "precision": 0.90,
        "recall": 0.90,
        "f1": 0.90,
        "auc_roc": 0.95,
        "false_positive_rate": 0.05
    }

@pytest.fixture(scope="function")
def temp_output_dir():
    """Create a temporary directory for test outputs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)

@pytest.fixture(scope="session")
def sample_config_file(test_data_dir):
    """Create a sample configuration file."""
    config_path = test_data_dir / "test_config.yaml"
    config_content = """
    model:
        name: scam_detector_v1
        type: transformer
        params:
            max_length: 512
            num_heads: 8
            num_layers: 6
    
    data:
        train_path: data/train
        val_path: data/val
        test_path: data/test
        
    training:
        batch_size: 32
        epochs: 10
        learning_rate: 0.0001
        
    evaluation:
        metrics:
            - accuracy
            - precision
            - recall
            - f1
            - auc_roc
    """
    config_path.write_text(config_content)
    return config_path
