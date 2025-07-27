#!/usr/bin/env python3
"""
Step 10: Run integration tests with the model trainer

Test the integration between MLThreatClassifier and ModelTrainer
"""

import json
from src.dmv_scam_analysis.ml.model_trainer import ModelTrainer

# Test messages from the original test_ml_classifier.py
test_messages = [
    {
        'text': "URGENT: Your driver's license has been suspended. Click http://dmv-license-verify.tk to pay $299 reinstatement fee within 24 hours.",
        'source': 'sms',
        'timestamp': '2025-06-27T14:30:00Z',
        'is_from_me': 0
    },
    {
        'text': "Your annual vehicle registration is due for renewal. Visit dmv.gov/renew or call 1-800-DMV-INFO.",
        'source': 'email',
        'timestamp': '2025-06-27T14:35:00Z',
        'is_from_me': 0
    },
    {
        'text': "DMV Notice: License expiration detected. Renew now at https://gov-dmv-renewal.ml. Immediate action required to avoid suspension.",
        'source': 'sms',
        'timestamp': '2025-06-27T14:40:00Z',
        'is_from_me': 0
    },
    {
        'text': "Reminder: Your vehicle registration expires next month. Renew online at www.dmv.gov or visit your local DMV office.",
        'source': 'email',
        'timestamp': '2025-06-27T14:45:00Z',
        'is_from_me': 0
    },
    {
        'text': "FINAL WARNING: DMV records show unpaid violations. Pay $450 at dmv-pay-center.ga now to avoid license suspension and legal action.",
        'source': 'sms',
        'timestamp': '2025-06-27T14:50:00Z',
        'is_from_me': 0
    },
    # Additional messages to ensure proper train/test split
    {
        'text': "ALERT: Penalty fee of $350 is due immediately. Avoid arrest by paying at dmv-urgent-pay.com within 6 hours.",
        'source': 'sms',
        'timestamp': '2025-06-27T15:00:00Z',
        'is_from_me': 0
    },
    {
        'text': "DMV office hours: Monday-Friday 8AM-5PM, Saturday 9AM-1PM. Visit dmv.gov for locations and services.",
        'source': 'email',
        'timestamp': '2025-06-27T15:05:00Z',
        'is_from_me': 0
    },
    {
        'text': "Your driver's license renewal notice has been mailed to your address. Visit www.dmv.gov for online renewal options.",
        'source': 'email',
        'timestamp': '2025-06-27T15:10:00Z',
        'is_from_me': 0
    }
]

# Test ModelTrainer
trainer = ModelTrainer()

# Create training data with alternating labels as specified in task
training_data = [
    {'text': msg['text'], 'label': 'scam' if i % 2 else 'legitimate'} 
    for i, msg in enumerate(test_messages)
]

# Save training data
with open('test_training_data.json', 'w') as f:
    json.dump(training_data, f)

print("🧪 Training data created with labels:")
for i, item in enumerate(training_data):
    print(f"  Message {i+1}: {item['label']}")

# Train classifier
print("\n🎓 Training classifier...")
results = trainer.train_classifier('test_training_data.json', 'models/test_classifier.pkl')

if results:
    print(f"✅ Training completed - Accuracy: {results['accuracy']:.3f}")
else:
    print("❌ Training failed")
    exit(1)

# Load and test predictions
print("\n📥 Loading trained model...")
model = trainer.load_model('models/test_classifier.pkl')

if model:
    print("✅ Model loaded successfully")
    
    # Make predictions on original test messages
    print("\n🔮 Making predictions...")
    predictions = trainer.predict(model, [msg['text'] for msg in test_messages])
    
    if predictions:
        print("\n📋 Results:")
        for i, pred in enumerate(predictions):
            label = 'Scam' if pred['prediction'] == 1 else 'Legitimate'
            confidence = pred['confidence']
            print(f"Message {i+1}: {label} (confidence: {confidence:.3f})")
            print(f"  Text: {pred['text'][:60]}...")
    else:
        print("❌ Predictions failed")
else:
    print("❌ Model loading failed")

print("\n✅ Integration test completed!")
