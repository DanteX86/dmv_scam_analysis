#!/usr/bin/env python3
"""
Enhanced Anomaly Detection Test with Parameter Tuning
DMV Scam Analysis Project

Testing different Isolation Forest parameters and statistical thresholds
to improve anomaly detection sensitivity.
"""

import pandas as pd
import json
import sys
import os
import numpy as np

# Add src to path
sys.path.insert(0, 'src')

# Import the classifier directly
try:
    from dmv_scam_analysis.core.classifier import MLThreatClassifier
except ImportError:
    print("Error importing MLThreatClassifier. Trying direct import...")
    sys.path.append(os.path.join(os.getcwd(), 'src', 'dmv_scam_analysis', 'core'))
    from classifier import MLThreatClassifier

# Import sklearn directly for parameter testing
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

def test_isolation_forest_parameters(X_scaled, contaminations=[0.1, 0.2, 0.3, 0.4, 0.5]):
    """Test different contamination parameters for Isolation Forest"""
    print("\n🔧 Testing Isolation Forest Parameters:")
    
    results = {}
    for contamination in contaminations:
        iso_forest = IsolationForest(contamination=contamination, random_state=42)
        labels = iso_forest.fit_predict(X_scaled)
        scores = iso_forest.decision_function(X_scaled)
        
        anomaly_count = np.sum(labels == -1)
        anomaly_ratio = anomaly_count / len(labels)
        
        results[contamination] = {
            'anomaly_count': anomaly_count,
            'anomaly_ratio': anomaly_ratio,
            'anomaly_detected': -1 in labels,
            'scores': scores,
            'min_score': np.min(scores),
            'max_score': np.max(scores),
            'mean_score': np.mean(scores)
        }
        
        print(f"  Contamination {contamination}: {anomaly_count}/{len(labels)} anomalies ({anomaly_ratio:.2%})")
        print(f"    Score range: [{np.min(scores):.3f}, {np.max(scores):.3f}], mean: {np.mean(scores):.3f}")
    
    return results

def test_manual_anomaly_detection():
    """Test manual anomaly detection implementation"""
    print("\n🔧 Testing Manual Anomaly Detection Implementation")
    
    # Initialize classifier
    classifier = MLThreatClassifier(output_dir="./test_output")
    
    # Create test data with clear anomalies
    test_data = [
        # Normal messages
        {
            "id": 1,
            "text": "Your vehicle registration expires in 30 days. Please renew.",
            "timestamp": "2024-01-15 10:00:00",
            "is_from_me": 0,
            "readable_date": "2024-01-15 10:00:00"
        },
        {
            "id": 2,
            "text": "Reminder: Registration renewal due soon.",
            "timestamp": "2024-01-15 10:30:00",
            "is_from_me": 0,
            "readable_date": "2024-01-15 10:30:00"
        },
        # Anomalous message - very different characteristics
        {
            "id": 3,
            "text": "URGENT!!!!!!! DMV WILL ARREST YOU TODAY!!!!!!! CLICK NOW AT SCAM-SITE.TK OR GO TO JAIL!!!!!!! PAY $999 IMMEDIATELY!!!!!!! " * 10,  # Very long and repetitive
            "timestamp": "2024-01-15 03:00:00",  # 3 AM
            "is_from_me": 0,
            "readable_date": "2024-01-15 03:00:00"
        }
    ]
    
    df = pd.DataFrame(test_data)
    
    # Extract features manually
    feature_data = classifier.extract_ml_features(df)
    if not feature_data:
        print("❌ Failed to extract features")
        return
    
    X = feature_data['features']
    print(f"📊 Extracted {len(X.columns)} features from {len(X)} messages")
    
    # Print some feature values
    print(f"Feature values for comparison:")
    for i, col in enumerate(X.columns[:10]):  # Show first 10 features
        print(f"  {col}: {X[col].values}")
    
    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    print(f"Scaled feature matrix shape: {X_scaled.shape}")
    print(f"Scaled feature statistics:")
    print(f"  Min: {np.min(X_scaled):.3f}, Max: {np.max(X_scaled):.3f}")
    print(f"  Mean: {np.mean(X_scaled):.3f}, Std: {np.std(X_scaled):.3f}")
    
    # Test different parameters
    iso_results = test_isolation_forest_parameters(X_scaled)
    
    # Test statistical outliers with different thresholds
    print(f"\n🔧 Testing Statistical Outlier Detection:")
    thresholds = [1.0, 1.5, 2.0, 2.5, 3.0]
    
    for threshold in thresholds:
        outlier_count = 0
        outlier_features = []
        
        for i, feature_name in enumerate(feature_data['feature_names']):
            feature_values = X.iloc[:, i]
            if len(feature_values) > 1 and feature_values.std() > 0:
                z_scores = np.abs((feature_values - feature_values.mean()) / feature_values.std())
                outliers_in_feature = np.sum(z_scores > threshold)
                if outliers_in_feature > 0:
                    outlier_count += outliers_in_feature
                    for j, z_score in enumerate(z_scores):
                        if z_score > threshold:
                            outlier_features.append({
                                'message_id': j,
                                'feature': feature_name,
                                'z_score': z_score,
                                'value': feature_values.iloc[j]
                            })
        
        print(f"  Threshold {threshold}: {outlier_count} outliers across {len(outlier_features)} feature-message pairs")
    
    # Try the classifier's detect_anomalies method
    print(f"\n🔧 Testing Classifier's detect_anomalies Method:")
    anomaly_results = classifier.detect_anomalies(df)
    
    if 'error' in anomaly_results:
        print(f"❌ Error: {anomaly_results['error']}")
    else:
        print(f"✅ Results from classifier:")
        print(f"  Anomaly likelihood: {anomaly_results['overall_assessment']['anomaly_likelihood']}%")
        print(f"  Primary concerns: {anomaly_results['overall_assessment']['primary_concerns']}")
        print(f"  Isolation Forest anomaly: {anomaly_results['isolation_forest']['is_anomaly']}")
        print(f"  Statistical outliers: {anomaly_results['statistical_outliers']['outlier_count']}")
    
    return iso_results, anomaly_results

def create_extreme_anomaly_test():
    """Create an extreme anomaly test case"""
    print("\n🚨 Testing Extreme Anomaly Cases")
    
    classifier = MLThreatClassifier(output_dir="./test_output")
    
    # Create extreme contrast between normal and anomalous
    extreme_data = [
        # Several normal messages to establish baseline
        {
            "id": 1,
            "text": "Registration renewal notice",
            "timestamp": "2024-01-15 10:00:00",
            "is_from_me": 0,
            "readable_date": "2024-01-15 10:00:00"
        },
        {
            "id": 2,
            "text": "Please renew by due date",
            "timestamp": "2024-01-15 10:30:00",
            "is_from_me": 0,
            "readable_date": "2024-01-15 10:30:00"
        },
        {
            "id": 3,
            "text": "Thank you for your renewal",
            "timestamp": "2024-01-15 11:00:00",
            "is_from_me": 0,
            "readable_date": "2024-01-15 11:00:00"
        },
        {
            "id": 4,
            "text": "Vehicle registration confirmed",
            "timestamp": "2024-01-15 11:30:00",
            "is_from_me": 0,
            "readable_date": "2024-01-15 11:30:00"
        },
        # One extreme anomaly
        {
            "id": 5,
            "text": "!" * 1000 + "URGENT DMV SCAM" + "!" * 1000 + "CLICK FAKE-SITE.TK NOW" + "!" * 1000,  # 3000+ character spam
            "timestamp": "2024-01-15 04:00:00",  # 4 AM
            "is_from_me": 0,
            "readable_date": "2024-01-15 04:00:00"
        }
    ]
    
    df = pd.DataFrame(extreme_data)
    
    print(f"📊 Testing with {len(df)} messages:")
    for i, row in df.iterrows():
        text_preview = row['text'][:50] + "..." if len(row['text']) > 50 else row['text']
        print(f"  {i+1}. [{row['readable_date']}] {text_preview} (length: {len(row['text'])})")
    
    # Test anomaly detection
    anomaly_results = classifier.detect_anomalies(df)
    
    print(f"\n🔍 EXTREME ANOMALY TEST RESULTS:")
    if 'error' in anomaly_results:
        print(f"❌ Error: {anomaly_results['error']}")
    else:
        # Display results as requested in the task
        overall_assessment = anomaly_results.get('overall_assessment', {})
        anomaly_likelihood = overall_assessment.get('anomaly_likelihood', 0)
        primary_concerns = overall_assessment.get('primary_concerns', [])
        
        print(f"Anomaly likelihood: {anomaly_likelihood}%")
        print(f"Primary concerns: {primary_concerns}")
        
        # Show detailed breakdown
        iso_forest = anomaly_results.get('isolation_forest', {})
        statistical_outliers = anomaly_results.get('statistical_outliers', {})
        
        print(f"\nDetailed Results:")
        print(f"  Isolation Forest:")
        print(f"    - Anomaly detected: {iso_forest.get('is_anomaly', False)}")
        print(f"    - Anomaly score: {iso_forest.get('anomaly_score', 0):.3f}")
        
        print(f"  Statistical Outliers:")
        print(f"    - Count: {statistical_outliers.get('outlier_count', 0)}")
        
        if statistical_outliers.get('outlier_features'):
            print(f"    - Top outlier features:")
            for feature in statistical_outliers['outlier_features'][:5]:
                print(f"      * {feature['feature']}: z-score={feature['z_score']:.2f}, value={feature['value']:.2f}")

def main():
    print("🔧 Enhanced Anomaly Detection Parameter Tuning")
    print("=" * 80)
    
    # Test manual implementation
    print("\n1️⃣ Testing Manual Implementation")
    manual_results = test_manual_anomaly_detection()
    
    # Test extreme cases
    print("\n2️⃣ Testing Extreme Anomaly Cases")
    create_extreme_anomaly_test()
    
    # Test with existing sample data but more parameters
    print("\n3️⃣ Testing with Sample Data and Multiple Parameters")
    
    try:
        with open('test_data/sample_messages.json', 'r') as f:
            sample_data = json.load(f)
    except FileNotFoundError:
        print("❌ Sample data file not found, skipping this test")
        return 0
    
    classifier = MLThreatClassifier(output_dir="./test_output")
    df = pd.DataFrame(sample_data)
    
    print(f"📊 Testing sample data with {len(df)} messages")
    
    # Try different contamination values
    feature_data = classifier.extract_ml_features(df)
    if feature_data:
        X = feature_data['features']
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        print(f"Feature matrix: {X_scaled.shape}")
        iso_results = test_isolation_forest_parameters(X_scaled, [0.1, 0.2, 0.3, 0.4, 0.5])
        
        # Show which contamination value detects the most anomalies
        best_contamination = max(iso_results.keys(), key=lambda k: iso_results[k]['anomaly_count'])
        print(f"\n🎯 Best contamination parameter: {best_contamination}")
        print(f"   Detected {iso_results[best_contamination]['anomaly_count']} anomalies")
    
    print(f"\n✅ Enhanced anomaly detection testing completed!")
    print(f"   Tested multiple parameter configurations and extreme cases.")
    
    return 0

if __name__ == "__main__":
    exit(main())
