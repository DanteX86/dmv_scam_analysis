import pandas as pd
from src.dmv_scam_analysis.core.classifier import MLThreatClassifier

# Test messages
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
    }
]

# Create DataFrame
df = pd.DataFrame(test_messages)

# Initialize classifier
classifier = MLThreatClassifier(output_dir='.')

# Extract features and train model
print("Extracting features and training model...")
feature_data = classifier.extract_ml_features(df, include_labels=True)
if feature_data:
    print("Features extracted:")
    print(f"Number of features: {len(feature_data['feature_names'])}")
    print("Sample features:")
    for name in feature_data['feature_names'][:5]:
        print(f"  - {name}")

    print("\nTraining model...")
    training_results = classifier.train_threat_classifier(feature_data)
    
    if isinstance(training_results, dict) and 'training_results' in training_results:
        print("\nTraining Results:")
        print(f"Best Model: {training_results['best_model']}")
        print(f"Label Distribution: {training_results['label_distribution']}")
        
        for model_name, metrics in training_results['training_results'].items():
            if isinstance(metrics, dict) and 'error' not in metrics:
                print(f"\n{model_name} Performance:")
                print(f"  Accuracy: {metrics['accuracy']:.2f}")
                print(f"  Precision: {metrics['precision']:.2f}")
                print(f"  Recall: {metrics['recall']:.2f}")
                print(f"  F1 Score: {metrics['f1_score']:.2f}")
                
                if 'feature_importance' in metrics:
                    print("\n  Top 5 Important Features:")
                    sorted_features = sorted(
                        metrics['feature_importance'].items(),
                        key=lambda x: x[1],
                        reverse=True
                    )[:5]
                    for feature, importance in sorted_features:
                        print(f"    - {feature}: {importance:.3f}")
    else:
        print("Error in training results:", training_results)

# Make predictions
print("\nMaking predictions...")
predictions = classifier.predict_threat_classification(df)
if 'predictions' in predictions:
    print("\nPrediction Results:")
    for i, (pred, text) in enumerate(zip(predictions['predictions'], df['text'])):
        print(f"\nMessage {i+1}:")
        print(f"Text: {text[:100]}...")
        print(f"Classification: {pred}")
        if predictions.get('max_threat_probability') is not None:
            print(f"Threat Probability: {predictions['max_threat_probability']:.2f}")
        print(f"Risk Level: {predictions.get('threat_risk_level', 'Unknown')}")

# Detect anomalies
print("\nDetecting anomalies...")
anomalies = classifier.detect_anomalies(df)
if 'overall_assessment' in anomalies:
    print("\nAnomaly Detection Results:")
    print(f"Anomaly Likelihood: {anomalies['overall_assessment']['anomaly_likelihood']}%")
    if anomalies['overall_assessment']['primary_concerns']:
        print("Primary Concerns:")
        for concern in anomalies['overall_assessment']['primary_concerns']:
            print(f"  - {concern}")

# Generate full report
print("\nGenerating report...")
report = classifier.generate_ml_report("test_contact", {
    'predictions': predictions,
    'anomaly_detection': anomalies
})

print("\nRisk Assessment:")
print(f"Risk Score: {report['risk_assessment']['ml_risk_score']}/100")
print(f"Risk Level: {report['risk_assessment']['risk_level']}")
print("\nRisk Factors:")
for factor in report['risk_assessment']['risk_factors']:
    print(f"  - {factor}")

print("\nRecommendations:")
for rec in report['recommendations']:
    print(f"[{rec['priority']}] {rec['recommendation']}")
    print(f"    Rationale: {rec['rationale']}")
