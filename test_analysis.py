import sys
sys.path.append('/Users/romulusaugustus/dmv_scam_analysis/scripts')
import sys
sys.path.append('/Users/romulusaugustus/dmv_scam_analysis/scripts')

from ml_threat_classifier import MLThreatClassifier
from behavioral_analyzer import BehavioralAnalyzer
import pandas as pd

# Create test messages
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

# Initialize components
classifier = MLThreatClassifier(output_dir='.')
analyzer = BehavioralAnalyzer()

# Extract features and make prediction
feature_data = classifier.extract_ml_features(df)
if feature_data:
    # Train a quick model (this would use pre-trained model in production)
    classifier.train_threat_classifier(feature_data)
    
    # Get predictions
    predictions = classifier.predict_threat_classification(df)
    if 'predictions' in predictions:
        print(f"Classification: {predictions['predictions'][0]}")
        if 'max_threat_probability' in predictions:
            print(f"Threat Probability: {predictions['max_threat_probability']:.2f}")
        print(f"Risk Level: {predictions.get('threat_risk_level', 'Unknown')}")

# Get behavioral analysis
analysis = analyzer.analyze([message_data])
print(f"Behavioral Indicators: {', '.join(analysis['indicators'])}")
print(f"Confidence: {analysis['confidence']:.2f}")

# Get anomaly detection
anomalies = classifier.detect_anomalies(df)
if 'overall_assessment' in anomalies:
    print(f"Anomaly Likelihood: {anomalies['overall_assessment']['anomaly_likelihood']}%")
    if anomalies['overall_assessment']['primary_concerns']:
        print("Primary Concerns:")
        for concern in anomalies['overall_assessment']['primary_concerns']:
            print(f"  - {concern}")
