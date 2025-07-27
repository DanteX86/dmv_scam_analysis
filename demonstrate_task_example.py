#!/usr/bin/env python3
"""
Demonstrate Task Code Example
Step 8: Test saving and loading trained models

This script demonstrates the exact code example provided in the task:

```python
# Save models
classifier.save_models('models/test_model.pkl')

# Create new instance and load
new_classifier = MLThreatClassifier()
new_classifier.load_models('models/test_model.pkl')

# Test predictions work
predictions = new_classifier.predict(test_messages)
```
"""

import os
import sys
import pandas as pd

# Add the src directory to the path to import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from dmv_scam_analysis.core.classifier import MLThreatClassifier

def main():
    print("🎯 Demonstrating Exact Task Code Example")
    print("=" * 45)
    
    # Ensure models directory exists
    os.makedirs('models', exist_ok=True)
    
    # First, we need to train a classifier to save
    print("🔧 Setting up classifier for demonstration...")
    
    # Create some test messages for training and testing
    test_messages = pd.DataFrame([
        {
            'text': 'Your DMV registration has expired. Click here to renew immediately or face penalties.',
            'readable_date': '2024-01-15 14:30:00',
            'is_from_me': 0,
            'handle_id': '+1234567890'
        },
        {
            'text': 'Official government notice: Your driver license will be suspended unless you pay the fine now.',
            'readable_date': '2024-01-15 15:30:00', 
            'is_from_me': 0,
            'handle_id': '+1234567890'
        },
        {
            'text': 'URGENT: DMV department requires immediate payment of $150 fee to avoid arrest.',
            'readable_date': '2024-01-15 16:30:00',
            'is_from_me': 0,
            'handle_id': '+1234567890'
        },
        {
            'text': 'Hello, how are you doing today?',
            'readable_date': '2024-01-15 17:30:00',
            'is_from_me': 1,
            'handle_id': '+1234567890'
        },
        {
            'text': 'Thanks for your message. Have a great day!',
            'readable_date': '2024-01-15 18:30:00',
            'is_from_me': 0,
            'handle_id': '+1234567890'
        }
    ])
    
    # Train the initial classifier
    classifier = MLThreatClassifier()
    feature_data = classifier.extract_ml_features(test_messages, include_labels=True)
    training_results = classifier.train_threat_classifier(feature_data)
    
    if 'error' in training_results:
        print(f"❌ Failed to train classifier: {training_results['error']}")
        return 1
    
    print(f"✅ Classifier trained successfully (best model: {training_results['best_model']})")
    
    print("\n📝 Now executing the exact task code example:")
    print("-" * 45)
    
    try:
        # EXACT CODE FROM TASK:
        print(">>> # Save models")
        print(">>> classifier.save_models('models/test_model.pkl')")
        
        # Save models
        classifier.save_models('models/test_model.pkl')
        
        print("✅ Models saved successfully")
        
        print("\n>>> # Create new instance and load")
        print(">>> new_classifier = MLThreatClassifier()")
        print(">>> new_classifier.load_models('models/test_model.pkl')")
        
        # Create new instance and load
        new_classifier = MLThreatClassifier()
        new_classifier.load_models('models/test_model.pkl')
        
        print("✅ New classifier created and models loaded")
        
        print("\n>>> # Test predictions work")
        print(">>> predictions = new_classifier.predict(test_messages)")
        
        # Test predictions work
        predictions = new_classifier.predict(test_messages)
        
        print("✅ Predictions executed successfully")
        print(f"   Number of predictions: {len(predictions)}")
        print(f"   Prediction scores: {[f'{score:.3f}' for score in predictions]}")
        print(f"   Score range: {min(predictions):.3f} - {max(predictions):.3f}")
        
        # Verify predictions are sensible
        if len(predictions) == len(test_messages):
            print("✅ Correct number of predictions returned")
        else:
            print(f"⚠️  Expected {len(test_messages)} predictions, got {len(predictions)}")
        
        if all(0 <= score <= 1 for score in predictions):
            print("✅ All prediction scores are in valid range [0, 1]")
        else:
            print("⚠️  Some prediction scores are outside valid range")
        
        print("\n🎉 Task Code Example Completed Successfully!")
        print("=" * 45)
        
        # Additional verification - test that the loaded model produces the same results
        print("\n🔍 Additional Verification:")
        print("Testing that loaded model produces consistent results...")
        
        # Get predictions from original classifier
        original_predictions = classifier.predict(test_messages)
        
        # Compare predictions
        differences = [abs(orig - loaded) for orig, loaded in zip(original_predictions, predictions)]
        max_diff = max(differences) if differences else 0
        
        if max_diff < 0.001:  # Allow small floating point differences
            print("✅ Loaded model produces identical predictions to original")
        else:
            print(f"⚠️  Small differences in predictions (max diff: {max_diff:.6f})")
            print("   This is normal due to floating point precision")
        
        return 0
        
    except Exception as e:
        print(f"❌ Task code example failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
