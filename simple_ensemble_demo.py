#!/usr/bin/env python3
"""
Simple Ensemble Demo Script
Demonstrates the exact code example from the task requirements
"""

import sys

# Import the classifier directly from the file
sys.path.insert(0, "src/dmv_scam_analysis/core")
from classifier import MLThreatClassifier

# Test messages as mentioned in the task example
test_messages = [
    {
        "text": "URGENT: Your driver's license has been suspended. Click http://dmv-license-verify.tk to pay $299 reinstatement fee within 24 hours."
    },
    {
        "text": "FINAL WARNING: DMV records show unpaid violations. Pay $450 at dmv-pay-center.ga now to avoid license suspension and legal action."
    },
    {
        "text": "Your annual vehicle registration is due for renewal. Visit dmv.gov/renew or call 1-800-DMV-INFO."
    },
    {
        "text": "Thanks for helping me with the DMV paperwork today. I'll let you know how it goes."
    },
    {
        "text": "DMV Notice: License expiration detected. Renew now at https://gov-dmv-renewal.ml. Immediate action required to avoid suspension."
    },
]

# Test ensemble functionality exactly as specified in the task
classifier = MLThreatClassifier()
texts = [msg["text"] for msg in test_messages]
labels = [0, 1, 1, 0, 1]  # Example labels as specified in task

print("🧪 Testing Ensemble Functionality")
print("=" * 50)

# Train ensemble
print("Training ensemble...")
ensemble_results = classifier.train_ensemble(texts=texts, labels=labels)

if "error" in ensemble_results:
    print(f"❌ Training failed: {ensemble_results['error']}")
else:
    print("✅ Ensemble training completed!")
    print(f"Models trained: {ensemble_results.get('ensemble_size', 0)}")
    print(f"Best model: {ensemble_results.get('best_model', 'Unknown')}")

# Make ensemble predictions
print("\nMaking ensemble predictions...")
predictions = classifier.predict_ensemble(texts)

if "error" in predictions:
    print(f"❌ Prediction failed: {predictions['error']}")
else:
    print("✅ Ensemble predictions completed!")
    # Display results exactly as specified in the task
    print(f"Mean predictions: {predictions['mean_prediction']}")
    print(f"Prediction variance: {predictions['std_prediction']}")

print("\n" + "=" * 50)
print("🎉 Demo completed successfully!")
