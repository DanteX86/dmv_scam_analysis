#!/usr/bin/env python3
"""
Direct Test of Anomaly Detection Capabilities
Using the exact code example from the task specification
"""

import pandas as pd
import json
import sys
import os

# Add src to path
sys.path.insert(0, 'src')

# Import the classifier directly
try:
    from dmv_scam_analysis.core.classifier import MLThreatClassifier
except ImportError:
    print("Error importing MLThreatClassifier. Trying direct import...")
    sys.path.append(os.path.join(os.getcwd(), 'src', 'dmv_scam_analysis', 'core'))
    from classifier import MLThreatClassifier

def main():
    print("🔍 Testing Anomaly Detection Capabilities")
    print("=" * 60)
    
    # Initialize classifier
    classifier = MLThreatClassifier(output_dir="./test_output")
    
    # Load sample data
    with open('test_data/sample_messages.json', 'r') as f:
        messages_data = json.load(f)
    
    df = pd.DataFrame(messages_data)
    print(f"Loaded {len(df)} messages for testing")
    print(f"Sample message: {df.iloc[0]['text'][:100]}...")
    
    print("\n" + "="*60)
    print("TESTING SCENARIO 1: Sample Messages (Mixed Content)")
    print("="*60)
    
    # Test anomaly detection using the exact code from the task
    anomaly_results = classifier.detect_anomalies(df)
    print(f"Anomaly likelihood: {anomaly_results['overall_assessment']['anomaly_likelihood']}%")
    print(f"Primary concerns: {anomaly_results['overall_assessment']['primary_concerns']}")
    
    # Show additional details
    print(f"\nDetailed Results:")
    print(f"  Isolation Forest Anomaly: {anomaly_results['isolation_forest']['is_anomaly']}")
    print(f"  Isolation Forest Score: {anomaly_results['isolation_forest']['anomaly_score']:.3f}")
    print(f"  Statistical Outliers: {anomaly_results['statistical_outliers']['outlier_count']}")
    
    if anomaly_results['statistical_outliers']['outlier_features']:
        print(f"  Top Outlier Features:")
        for feature in anomaly_results['statistical_outliers']['outlier_features'][:3]:
            print(f"    - {feature['feature']}: z-score={feature['z_score']:.2f}")
    
    print("\n" + "="*60)
    print("TESTING SCENARIO 2: Burst Messaging Pattern")
    print("="*60)
    
    # Create burst messaging data
    burst_data = []
    base_time = "2024-01-15 02:00:"
    for i in range(15):  # 15 messages in rapid succession at 2 AM
        burst_data.append({
            "id": i + 1,
            "text": f"URGENT! DMV SUSPENSION #{i+1}: Act immediately! Visit scam-dmv.tk NOW!",
            "timestamp": f"{base_time}{i:02d}:00",
            "is_from_me": 0,
            "readable_date": f"{base_time}{i:02d}:00",
            "handle_id": "scammer@fake.tk"
        })
    
    burst_df = pd.DataFrame(burst_data)
    
    # Test anomaly detection on burst pattern
    anomaly_results = classifier.detect_anomalies(burst_df)
    print(f"Anomaly likelihood: {anomaly_results['overall_assessment']['anomaly_likelihood']}%")
    print(f"Primary concerns: {anomaly_results['overall_assessment']['primary_concerns']}")
    
    print("\n" + "="*60)
    print("TESTING SCENARIO 3: Normal vs Anomalous Comparison")
    print("="*60)
    
    # Normal pattern
    normal_data = [{
        "id": 1,
        "text": "Your vehicle registration renewal notice. Please renew by the due date.",
        "timestamp": "2024-01-15 10:00:00",
        "is_from_me": 0,
        "readable_date": "2024-01-15 10:00:00",
        "handle_id": "dmv@ca.gov"
    }]
    
    # Anomalous pattern
    anomalous_data = [{
        "id": 1,
        "text": "URGENT!!! DMV WILL ARREST YOU!!! Pay $500 NOW at sketchy-dmv.tk or GO TO JAIL!!! This is your FINAL WARNING!!! Click here immediately: http://fake-site.ru/pay-now",
        "timestamp": "2024-01-15 03:00:00",  # 3 AM
        "is_from_me": 0,
        "readable_date": "2024-01-15 03:00:00",
        "handle_id": "urgent@scam.tk"
    }]
    
    print("Testing NORMAL message:")
    normal_df = pd.DataFrame(normal_data)
    anomaly_results = classifier.detect_anomalies(normal_df)
    print(f"  Anomaly likelihood: {anomaly_results['overall_assessment']['anomaly_likelihood']}%")
    print(f"  Primary concerns: {anomaly_results['overall_assessment']['primary_concerns']}")
    
    print("\nTesting ANOMALOUS message:")
    anomalous_df = pd.DataFrame(anomalous_data)
    anomaly_results = classifier.detect_anomalies(anomalous_df)
    print(f"  Anomaly likelihood: {anomaly_results['overall_assessment']['anomaly_likelihood']}%")
    print(f"  Primary concerns: {anomaly_results['overall_assessment']['primary_concerns']}")
    
    print("\n" + "="*60)
    print("TESTING SCENARIO 4: Statistical Outliers")
    print("="*60)
    
    # Create data with clear statistical outliers
    outlier_data = [
        {
            "id": 1,
            "text": "DMV",  # Very short
            "timestamp": "2024-01-15 10:00:00",
            "is_from_me": 0,
            "readable_date": "2024-01-15 10:00:00",
            "handle_id": "test@dmv.gov"
        },
        {
            "id": 2,
            "text": "URGENT URGENT URGENT " * 100,  # Very long and repetitive
            "timestamp": "2024-01-15 10:01:00",
            "is_from_me": 0,
            "readable_date": "2024-01-15 10:01:00",
            "handle_id": "spam@fake.com"
        },
        {
            "id": 3,
            "text": "CLICK NOW!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",  # Many exclamations
            "timestamp": "2024-01-15 04:00:00",  # 4 AM
            "is_from_me": 0,
            "readable_date": "2024-01-15 04:00:00",
            "handle_id": "urgent@scam.tk"
        }
    ]
    
    outlier_df = pd.DataFrame(outlier_data)
    
    print("Testing STATISTICAL OUTLIERS:")
    anomaly_results = classifier.detect_anomalies(outlier_df)
    print(f"  Anomaly likelihood: {anomaly_results['overall_assessment']['anomaly_likelihood']}%")
    print(f"  Primary concerns: {anomaly_results['overall_assessment']['primary_concerns']}")
    
    if anomaly_results['statistical_outliers']['outlier_features']:
        print(f"  Outlier features detected:")
        for feature in anomaly_results['statistical_outliers']['outlier_features']:
            print(f"    - {feature['feature']}: z-score={feature['z_score']:.2f}, value={feature['value']:.2f}")
    
    print("\n✅ Anomaly detection testing completed!")
    
    return 0

if __name__ == "__main__":
    exit(main())
