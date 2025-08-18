#!/usr/bin/env python3
"""Debug script to test the training process."""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from scripts.ml_threat_classifier import MLThreatClassifier

# Create a small dataset for testing
texts = [
    "urgent payment required",
    "license expiration notice",
    "dmv registration renewal",
    "verify your information",
    "click here to pay"
]

labels = [1, 1, 0, 1, 1]

# Create classifier
classifier = MLThreatClassifier()

print("Creating classifier...")
try:
    print("Training classifier...")
    result = classifier.train(texts=texts, labels=labels)
    print(f"Training result: {result}")
    
    print("Model trained successfully!")
    
    # Test prediction
    predictions = classifier.predict(texts)
    print(f"Predictions: {predictions}")
    
except Exception as e:
    print(f"Error during training: {e}")
    import traceback
    traceback.print_exc()
