#!/usr/bin/env python3
"""
Integration test for MLThreatClassifier and ModelTrainer
"""

import json

from dmv_scam_analysis.ml.model_trainer import ModelTrainer


def main():
    print("🧪 Starting integration test for MLThreatClassifier and ModelTrainer")

    # Test messages (expanded dataset for proper train/test split)
    test_messages = [
        {
            "text": "URGENT: Your driver's license has been suspended. Click http://dmv-license-verify.tk to pay $299 reinstatement fee within 24 hours."
        },
        {
            "text": "Your annual vehicle registration is due for renewal. Visit dmv.gov/renew or call 1-800-DMV-INFO."
        },
        {
            "text": "DMV Notice: License expiration detected. Renew now at https://gov-dmv-renewal.ml. Immediate action required to avoid suspension."
        },
        {
            "text": "Reminder: Your vehicle registration expires next month. Renew online at www.dmv.gov or visit your local DMV office."
        },
        {
            "text": "FINAL WARNING: DMV records show unpaid violations. Pay $450 at dmv-pay-center.ga now to avoid license suspension and legal action."
        },
        # Additional scam messages
        {
            "text": "ALERT: Penalty fee of $350 is due immediately. Avoid arrest by paying at dmv-urgent-pay.com within 6 hours."
        },
        {
            "text": "DMV FINAL NOTICE: Your license will be suspended tomorrow. Pay $275 fine at quick-dmv-resolution.net now."
        },
        {
            "text": "CRITICAL: Outstanding DMV violation detected. Click dmv-violation-center.org to pay $425 and avoid legal consequences."
        },
        # Additional legitimate messages
        {
            "text": "This is a reminder that your vehicle registration will expire on 12/31/2024. Please renew at your local DMV office."
        },
        {
            "text": "Your driver's license renewal notice has been mailed to your address. Visit www.dmv.gov for online renewal options."
        },
        {
            "text": "Thank you for visiting the DMV. Your appointment confirmation number is DMV-2024-1234. Please arrive 15 minutes early."
        },
        {
            "text": "DMV office hours: Monday-Friday 8AM-5PM, Saturday 9AM-1PM. Visit dmv.gov for locations and services."
        },
    ]

    # Test ModelTrainer
    print("\n🤖 Initializing ModelTrainer...")
    trainer = ModelTrainer()

    # Create training data with alternating labels as requested
    print("\n📝 Creating training data...")
    training_data = [
        {"text": msg["text"], "label": "scam" if i % 2 else "legitimate"}
        for i, msg in enumerate(test_messages)
    ]

    print("Training data labels:")
    for i, item in enumerate(training_data):
        print(f"  Message {i+1}: {item['label']}")

    # Save training data
    print("\n💾 Saving training data to test_training_data.json...")
    with open("test_training_data.json", "w") as f:
        json.dump(training_data, f, indent=2)

    # Train classifier
    print("\n🎓 Training classifier...")
    results = trainer.train_classifier(
        "test_training_data.json", "models/test_classifier.pkl"
    )

    if results:
        print("\n📊 Training Results:")
        print(f"  Model type: {results['model_type']}")
        print(f"  Training samples: {results['training_samples']}")
        print(f"  Test samples: {results['test_samples']}")
        print(f"  Accuracy: {results['accuracy']:.3f}")
        print(f"  Training timestamp: {results['training_timestamp']}")

        if "classification_report" in results:
            report = results["classification_report"]
            print(f"  Precision (macro avg): {report['macro avg']['precision']:.3f}")
            print(f"  Recall (macro avg): {report['macro avg']['recall']:.3f}")
            print(f"  F1-score (macro avg): {report['macro avg']['f1-score']:.3f}")
    else:
        print("❌ Training failed!")
        return

    # Load and test predictions
    print("\n📥 Loading trained model...")
    model = trainer.load_model("models/test_classifier.pkl")

    if model:
        print("✅ Model loaded successfully")

        # Make predictions
        print("\n🔮 Making predictions...")
        predictions = trainer.predict(model, [msg["text"] for msg in test_messages])

        if predictions:
            print("\n📋 Prediction Results:")
            for i, pred in enumerate(predictions):
                print(f"\nMessage {i+1}:")
                print(f"  Text: {pred['text'][:80]}...")
                print(
                    f"  Prediction: {'Scam' if pred['prediction'] == 1 else 'Legitimate'}"
                )
                print(f"  Confidence: {pred['confidence']:.3f}")
                print(f"  Probability: {pred['probability']:.3f}")
        else:
            print("❌ Prediction failed!")
    else:
        print("❌ Model loading failed!")

    print("\n✅ Integration test completed!")


if __name__ == "__main__":
    main()
