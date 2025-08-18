#!/usr/bin/env python3
"""
This file contains the exact code example from the task specification
"""

import json
import os
import sys
from typing import Any

import pandas as pd

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from dmv_scam_analysis.core.classifier import MLThreatClassifier

# Initialize classifier
classifier = MLThreatClassifier()

# Test with different datasets
for dataset in ["legitimate", "scam", "mixed"]:
    # Load the dataset
    with open(f"test_data/{dataset}_messages.json", "r") as f:
        data = json.load(f)

    # Handle different JSON structures
    if "messages" in data:
        messages = data["messages"]
    else:
        messages = data

    df = pd.DataFrame(messages)

    # Ensure we have required columns for proper analysis
    if "readable_date" not in df.columns and "timestamp" in df.columns:
        df["readable_date"] = pd.to_datetime(df["timestamp"])
    elif "readable_date" not in df.columns:
        # Generate synthetic timestamps for demonstration
        base_time = pd.Timestamp("2024-01-01 10:00:00")
        df["readable_date"] = [
            base_time + pd.Timedelta(hours=i) for i in range(len(df))
        ]

    if "is_from_me" not in df.columns:
        df["is_from_me"] = [i % 2 for i in range(len(df))]

    if "handle_id" not in df.columns:
        df["handle_id"] = [f"contact_{i % 3}" for i in range(len(df))]

    # Extract features and train
    features = classifier.extract_ml_features(df, include_labels=True)
    training_results = (
        classifier.train_threat_classifier(features) if features else None
    )

    # Make predictions
    predictions: dict[str, Any] = classifier.predict_threat_classification(df)

    # Evaluate accuracy
    print(f"Dataset: {dataset}")
    if training_results and "training_results" in training_results:
        print(
            f"Accuracy: {training_results['training_results']['random_forest']['accuracy']}"
        )
    else:
        print("Accuracy: N/A")
