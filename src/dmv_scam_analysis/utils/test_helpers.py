"""
Test Helper Functions for DMV Scam Analysis
"""

import json
import random
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import pandas as pd
import numpy as np
from faker import Faker

fake = Faker()

def generate_test_message(
    message_type: str = "scam",
    threat_level: float = 0.8,
    **kwargs
) -> Dict[str, Any]:
    """
    Generate a test message for analysis
    
    Args:
        message_type: Type of message ('scam', 'legitimate', 'phishing')
        threat_level: Threat level (0.0 to 1.0)
        **kwargs: Additional message properties
        
    Returns:
        dict: Test message data
    """
    base_message = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now().isoformat(),
        "sender": fake.email(),
        "recipient": fake.email(),
        "subject": fake.sentence(),
        "message": _generate_message_content(message_type),
        "label": message_type,
        "threat_score": threat_level,
        "metadata": {
            "source": "test_generator",
            "created_at": datetime.now().isoformat()
        }
    }
    
    # Override with any provided kwargs
    base_message.update(kwargs)
    
    return base_message

def _generate_message_content(message_type: str) -> str:
    """Generate message content based on type"""
    if message_type == "scam":
        templates = [
            "URGENT: Your DMV registration expires in {} days. Click {} to renew immediately.",
            "Your vehicle registration is SUSPENDED. Visit {} to resolve this issue.",
            "DMV NOTICE: Your license will be revoked unless you update your info at {}.",
            "FINAL WARNING: Your registration fees are overdue. Pay now at {}."
        ]
        return random.choice(templates).format(
            random.randint(1, 7),
            fake.url()
        )
    elif message_type == "legitimate":
        templates = [
            "Thank you for renewing your vehicle registration. Your new sticker will arrive in 5-7 business days.",
            "Your DMV appointment is confirmed for {} at {}.",
            "Registration renewal reminder: Your registration expires on {}.",
            "Your vehicle passed inspection. Certificate is valid until {}."
        ]
        return random.choice(templates).format(
            fake.date_between(start_date='+1d', end_date='+30d'),
            fake.time()
        )
    else:
        return fake.text(max_nb_chars=200)

def create_test_dataset(
    num_samples: int = 100,
    scam_ratio: float = 0.4,
    legitimate_ratio: float = 0.6,
    include_metadata: bool = True
) -> List[Dict[str, Any]]:
    """
    Create a balanced test dataset
    
    Args:
        num_samples: Total number of samples to generate
        scam_ratio: Ratio of scam messages
        legitimate_ratio: Ratio of legitimate messages
        include_metadata: Whether to include metadata fields
        
    Returns:
        list: List of test messages
    """
    if abs(scam_ratio + legitimate_ratio - 1.0) > 0.001:
        raise ValueError("Ratios must sum to 1.0")
    
    dataset = []
    
    # Generate scam messages
    num_scam = int(num_samples * scam_ratio)
    for _ in range(num_scam):
        message = generate_test_message(
            message_type="scam",
            threat_level=random.uniform(0.6, 1.0)
        )
        if not include_metadata:
            message.pop('metadata', None)
        dataset.append(message)
    
    # Generate legitimate messages
    num_legitimate = num_samples - num_scam
    for _ in range(num_legitimate):
        message = generate_test_message(
            message_type="legitimate",
            threat_level=random.uniform(0.0, 0.3)
        )
        if not include_metadata:
            message.pop('metadata', None)
        dataset.append(message)
    
    # Shuffle the dataset
    random.shuffle(dataset)
    
    return dataset

def create_test_dataframe(
    num_samples: int = 100,
    include_nulls: bool = False,
    include_duplicates: bool = False
) -> pd.DataFrame:
    """
    Create a test pandas DataFrame
    
    Args:
        num_samples: Number of samples to generate
        include_nulls: Whether to include null values
        include_duplicates: Whether to include duplicate values
        
    Returns:
        pd.DataFrame: Test DataFrame
    """
    data = {
        'datetime': pd.date_range('2025-01-01', periods=num_samples),
        'contact_id': [f'user_{i}' for i in range(num_samples)],
        'text': [fake.text(max_nb_chars=100) for _ in range(num_samples)],
        'is_from_me': [random.choice([True, False]) for _ in range(num_samples)]
    }
    
    df = pd.DataFrame(data)
    
    if include_nulls:
        # Add some null values
        null_indices = random.sample(range(num_samples), min(5, num_samples // 10))
        df.loc[null_indices, 'text'] = None
    
    if include_duplicates:
        # Add duplicate contact_ids
        duplicate_indices = random.sample(range(num_samples), min(3, num_samples // 20))
        df.loc[duplicate_indices, 'contact_id'] = df.loc[0, 'contact_id']
    
    return df

def create_mock_analysis_result(
    message_id: str,
    threat_score: float = 0.5,
    confidence: float = 0.8
) -> Dict[str, Any]:
    """
    Create a mock analysis result
    
    Args:
        message_id: ID of the analyzed message
        threat_score: Threat score (0.0 to 1.0)
        confidence: Confidence level (0.0 to 1.0)
        
    Returns:
        dict: Mock analysis result
    """
    return {
        "message_id": message_id,
        "threat_score": threat_score,
        "confidence": confidence,
        "analysis_type": "nlp",
        "features": {
            "urgency_keywords": random.randint(0, 5),
            "suspicious_links": random.randint(0, 3),
            "sentiment_polarity": random.uniform(-1, 1),
            "readability_score": random.uniform(0, 100)
        },
        "indicators": [
            {"type": "keyword", "value": "urgent", "score": 0.8},
            {"type": "domain", "value": "suspicious-domain.com", "score": 0.9}
        ],
        "timestamp": datetime.now().isoformat(),
        "processing_time": random.uniform(0.1, 2.0)
    }

def save_test_data(data: List[Dict[str, Any]], filepath: str) -> None:
    """
    Save test data to a JSON file
    
    Args:
        data: Test data to save
        filepath: Path to save the file
    """
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2, default=str)

def load_test_data(filepath: str) -> List[Dict[str, Any]]:
    """
    Load test data from a JSON file
    
    Args:
        filepath: Path to load the file from
        
    Returns:
        list: Loaded test data
    """
    with open(filepath, 'r') as f:
        return json.load(f)

def create_performance_test_data(
    num_messages: int = 1000,
    message_size_kb: int = 5
) -> List[Dict[str, Any]]:
    """
    Create test data for performance testing
    
    Args:
        num_messages: Number of messages to generate
        message_size_kb: Approximate size of each message in KB
        
    Returns:
        list: Performance test data
    """
    target_chars = message_size_kb * 1000  # Approximate chars per KB
    
    dataset = []
    for i in range(num_messages):
        message = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now().isoformat(),
            "sender": fake.email(),
            "message": fake.text(max_nb_chars=target_chars),
            "label": random.choice(["scam", "legitimate"]),
            "batch_id": i // 100,  # Group into batches of 100
            "index": i
        }
        dataset.append(message)
    
    return dataset

def validate_test_results(
    results: List[Dict[str, Any]],
    expected_fields: List[str]
) -> Dict[str, Any]:
    """
    Validate test results structure
    
    Args:
        results: Test results to validate
        expected_fields: List of expected fields in each result
        
    Returns:
        dict: Validation report
    """
    validation_report = {
        "is_valid": True,
        "errors": [],
        "warnings": [],
        "total_results": len(results)
    }
    
    for i, result in enumerate(results):
        # Check for missing fields
        missing_fields = [field for field in expected_fields if field not in result]
        if missing_fields:
            validation_report["errors"].append(
                f"Result {i}: Missing fields: {missing_fields}"
            )
            validation_report["is_valid"] = False
        
        # Check for null values in required fields
        for field in expected_fields:
            if field in result and result[field] is None:
                validation_report["warnings"].append(
                    f"Result {i}: Field '{field}' is null"
                )
    
    return validation_report

def create_test_embeddings(
    num_samples: int = 100,
    embedding_dim: int = 384,
    seed: Optional[int] = None
) -> np.ndarray:
    """
    Create test embeddings for ML model testing
    
    Args:
        num_samples: Number of embedding vectors to generate
        embedding_dim: Dimension of each embedding vector
        seed: Random seed for reproducibility
        
    Returns:
        np.ndarray: Array of test embeddings with shape (num_samples, embedding_dim)
    """
    if seed is not None:
        np.random.seed(seed)
    
    # Generate embeddings with some structure to simulate real embeddings
    embeddings = np.random.normal(0, 1, (num_samples, embedding_dim))
    
    # Normalize embeddings to unit length (common for sentence embeddings)
    norms = np.linalg.norm(embeddings, axis=1, keepdims=True)
    embeddings = embeddings / (norms + 1e-8)  # Add small epsilon to avoid division by zero
    
    return embeddings

def create_test_embeddings_with_labels(
    num_samples: int = 100,
    embedding_dim: int = 384,
    num_classes: int = 2,
    seed: Optional[int] = None
) -> tuple[np.ndarray, np.ndarray]:
    """
    Create test embeddings with corresponding labels
    
    Args:
        num_samples: Number of embedding vectors to generate
        embedding_dim: Dimension of each embedding vector
        num_classes: Number of classes for labels
        seed: Random seed for reproducibility
        
    Returns:
        tuple: (embeddings, labels) where embeddings is shape (num_samples, embedding_dim)
               and labels is shape (num_samples,)
    """
    if seed is not None:
        np.random.seed(seed)
        random.seed(seed)
    
    # Generate embeddings
    embeddings = create_test_embeddings(num_samples, embedding_dim, seed)
    
    # Generate labels
    labels = np.random.randint(0, num_classes, num_samples)
    
    return embeddings, labels

def create_test_similarity_matrix(
    num_samples: int = 100,
    seed: Optional[int] = None
) -> np.ndarray:
    """
    Create a test similarity matrix for clustering/similarity testing
    
    Args:
        num_samples: Size of the square similarity matrix
        seed: Random seed for reproducibility
        
    Returns:
        np.ndarray: Symmetric similarity matrix with values between 0 and 1
    """
    if seed is not None:
        np.random.seed(seed)
    
    # Generate random similarity matrix
    similarity_matrix = np.random.rand(num_samples, num_samples)
    
    # Make it symmetric
    similarity_matrix = (similarity_matrix + similarity_matrix.T) / 2
    
    # Set diagonal to 1 (similarity with self)
    np.fill_diagonal(similarity_matrix, 1.0)
    
    return similarity_matrix
