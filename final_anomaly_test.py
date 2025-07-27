#!/usr/bin/env python3
"""
Final Comprehensive Anomaly Detection Test
DMV Scam Analysis Project

Testing the anomaly detection system with various scenarios as requested in the task:
- Normal communication patterns
- Burst messaging (many messages in short time)
- Unusual timing patterns (messages at odd hours)
- Statistical outliers in message length or content

Using the exact code from the task specification.
"""

import pandas as pd
import json
import sys
import os
from datetime import datetime, timedelta
import numpy as np

# Add src to path
sys.path.insert(0, 'src')

try:
    from dmv_scam_analysis.core.classifier import MLThreatClassifier
except ImportError:
    print("Error importing MLThreatClassifier. Trying direct import...")
    sys.path.append(os.path.join(os.getcwd(), 'src', 'dmv_scam_analysis', 'core'))
    from classifier import MLThreatClassifier

def create_test_scenarios():
    """Create comprehensive test scenarios for anomaly detection"""
    
    scenarios = {}
    
    # 1. Normal communication patterns
    scenarios['normal'] = [
        {
            "id": 1,
            "text": "Your vehicle registration expires in 30 days. Please renew at your convenience.",
            "timestamp": "2024-01-15 09:00:00",
            "is_from_me": 0,
            "readable_date": "2024-01-15 09:00:00"
        },
        {
            "id": 2,
            "text": "Registration renewal reminder. Visit DMV office or renew online.",
            "timestamp": "2024-01-15 09:30:00",
            "is_from_me": 0,
            "readable_date": "2024-01-15 09:30:00"
        },
        {
            "id": 3,
            "text": "Thank you for renewing your vehicle registration.",
            "timestamp": "2024-01-15 10:00:00",
            "is_from_me": 0,
            "readable_date": "2024-01-15 10:00:00"
        }
    ]
    
    # 2. Burst messaging (many messages in short time)
    base_time = datetime(2024, 1, 15, 14, 0, 0)
    burst_messages = []
    for i in range(12):  # 12 messages in 6 minutes
        timestamp = base_time + timedelta(seconds=i * 30)
        burst_messages.append({
            "id": i + 1,
            "text": f"URGENT MESSAGE #{i+1}: Your DMV account will be suspended! Act NOW!",
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "is_from_me": 0,
            "readable_date": timestamp.strftime("%Y-%m-%d %H:%M:%S")
        })
    scenarios['burst'] = burst_messages
    
    # 3. Unusual timing patterns (messages at odd hours)
    scenarios['odd_timing'] = [
        {
            "id": 1,
            "text": "CRITICAL DMV ALERT: Immediate action required to avoid legal consequences!",
            "timestamp": "2024-01-15 01:00:00",  # 1 AM
            "is_from_me": 0,
            "readable_date": "2024-01-15 01:00:00"
        },
        {
            "id": 2,
            "text": "URGENT: License suspension pending. Contact immediately.",
            "timestamp": "2024-01-15 03:30:00",  # 3:30 AM
            "is_from_me": 0,
            "readable_date": "2024-01-15 03:30:00"
        },
        {
            "id": 3,
            "text": "Final notice: Pay fees now or face arrest.",
            "timestamp": "2024-01-15 23:45:00",  # 11:45 PM
            "is_from_me": 0,
            "readable_date": "2024-01-15 23:45:00"
        }
    ]
    
    # 4. Statistical outliers in message length or content
    scenarios['outliers'] = [
        {
            "id": 1,
            "text": "DMV",  # Very short
            "timestamp": "2024-01-15 10:00:00",
            "is_from_me": 0,
            "readable_date": "2024-01-15 10:00:00"
        },
        {
            "id": 2,
            "text": ("URGENT!!!!!!! " * 50 + "DMV WILL ARREST YOU TODAY!!!!!!! " * 50 + 
                   "CLICK NOW AT SCAM-SITE.TK OR GO TO JAIL!!!!!!! " * 50 + 
                   "PAY $999 IMMEDIATELY!!!!!!! " * 50),  # Extremely long and repetitive
            "timestamp": "2024-01-15 10:01:00",
            "is_from_me": 0,
            "readable_date": "2024-01-15 10:01:00"
        },
        {
            "id": 3,
            "text": "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",  # All punctuation
            "timestamp": "2024-01-15 10:02:00",
            "is_from_me": 0,
            "readable_date": "2024-01-15 10:02:00"
        },
        {
            "id": 4,
            "text": "Visit http://dmv-fake.tk http://scam-dmv.ml http://urgent-dmv.ga http://alert-dmv.vip NOW!",  # Multiple suspicious URLs
            "timestamp": "2024-01-15 10:03:00",
            "is_from_me": 0,
            "readable_date": "2024-01-15 10:03:00"
        }
    ]
    
    return scenarios

def test_scenario(scenario_name, messages, classifier):
    """Test a specific scenario and display results using task specification format"""
    
    print(f"\n" + "="*70)
    print(f"TESTING SCENARIO: {scenario_name.upper()}")
    print("="*70)
    
    # Convert to DataFrame
    df = pd.DataFrame(messages)
    
    print(f"📊 Dataset: {len(messages)} messages")
    print(f"Time range: {df['readable_date'].min()} to {df['readable_date'].max()}")
    
    # Show message characteristics
    lengths = [len(msg['text']) for msg in messages]
    print(f"Message lengths: min={min(lengths)}, max={max(lengths)}, avg={np.mean(lengths):.1f}")
    
    # Test anomaly detection using the exact code from the task
    anomaly_results = classifier.detect_anomalies(df)
    
    if 'error' in anomaly_results:
        print(f"❌ Error in anomaly detection: {anomaly_results['error']}")
        return None
    
    # Display results as requested in the task specification
    print(f"\n🔍 ANOMALY DETECTION RESULTS:")
    print(f"Anomaly likelihood: {anomaly_results['overall_assessment']['anomaly_likelihood']}%")
    print(f"Primary concerns: {anomaly_results['overall_assessment']['primary_concerns']}")
    
    # Additional analysis
    iso_forest = anomaly_results.get('isolation_forest', {})
    statistical_outliers = anomaly_results.get('statistical_outliers', {})
    
    print(f"\n📈 Detailed Analysis:")
    print(f"  Isolation Forest:")
    print(f"    • Anomaly detected: {iso_forest.get('is_anomaly', False)}")
    print(f"    • Anomaly score: {iso_forest.get('anomaly_score', 0):.4f}")
    
    print(f"  Statistical Outliers:")
    print(f"    • Count: {statistical_outliers.get('outlier_count', 0)}")
    
    if statistical_outliers.get('outlier_features'):
        print(f"    • Top outlier features:")
        for i, feature in enumerate(statistical_outliers['outlier_features'][:3]):
            print(f"      {i+1}. {feature['feature']}: z-score={feature['z_score']:.2f}")
    
    return anomaly_results

def main():
    """Main function to run comprehensive anomaly detection testing"""
    
    print("🚀 COMPREHENSIVE ANOMALY DETECTION TESTING")
    print("="*80)
    print("Testing anomaly detection capabilities with various scenarios:")
    print("• Normal communication patterns")
    print("• Burst messaging (many messages in short time)")
    print("• Unusual timing patterns (messages at odd hours)")
    print("• Statistical outliers in message length or content")
    print("="*80)
    
    # Initialize classifier
    try:
        classifier = MLThreatClassifier(output_dir="./test_output")
        print("✅ ML Threat Classifier initialized successfully")
    except Exception as e:
        print(f"❌ Failed to initialize classifier: {e}")
        return 1
    
    # Create test scenarios
    scenarios = create_test_scenarios()
    
    # Store results for comparison
    all_results = {}
    
    # Test each scenario
    scenario_descriptions = {
        'normal': 'Normal Communication Patterns',
        'burst': 'Burst Messaging (Many messages in short time)',
        'odd_timing': 'Unusual Timing Patterns (Messages at odd hours)',
        'outliers': 'Statistical Outliers in Message Length/Content'
    }
    
    for scenario_key, messages in scenarios.items():
        scenario_name = scenario_descriptions[scenario_key]
        result = test_scenario(scenario_name, messages, classifier)
        if result:
            all_results[scenario_name] = result
    
    # Summary analysis
    print(f"\n" + "="*80)
    print("SUMMARY ANALYSIS")
    print("="*80)
    
    if all_results:
        print(f"{'Scenario':<50} {'Anomaly %':<12} {'ISO Forest':<12} {'Outliers':<10}")
        print("-" * 84)
        
        for scenario_name, result in all_results.items():
            overall = result.get('overall_assessment', {})
            iso_forest = result.get('isolation_forest', {})
            outliers = result.get('statistical_outliers', {})
            
            anomaly_pct = overall.get('anomaly_likelihood', 0)
            is_anomaly = "Yes" if iso_forest.get('is_anomaly', False) else "No"
            outlier_count = outliers.get('outlier_count', 0)
            
            print(f"{scenario_name:<50} {anomaly_pct:<12}% {is_anomaly:<12} {outlier_count:<10}")
        
        # Find most anomalous scenario
        anomaly_scores = {name: result.get('overall_assessment', {}).get('anomaly_likelihood', 0) 
                         for name, result in all_results.items()}
        
        if max(anomaly_scores.values()) > 0:
            most_anomalous = max(anomaly_scores, key=anomaly_scores.get)
            print(f"\n🎯 Most anomalous scenario: {most_anomalous} ({anomaly_scores[most_anomalous]}%)")
        else:
            print(f"\n🤔 No anomalies detected in any scenario")
            print(f"   This may indicate:")
            print(f"   • Need for parameter tuning")
            print(f"   • Insufficient feature diversity")
            print(f"   • Model requires more training data")
        
        # Show all primary concerns
        all_concerns = []
        for result in all_results.values():
            concerns = result.get('overall_assessment', {}).get('primary_concerns', [])
            all_concerns.extend(concerns)
        
        if all_concerns:
            print(f"\n🔍 All detected concerns:")
            for i, concern in enumerate(set(all_concerns), 1):
                print(f"   {i}. {concern}")
        else:
            print(f"\n🔍 No specific concerns identified across all scenarios")
    
    print(f"\n" + "="*80)
    print("TESTING COMPLETED")
    print("="*80)
    print(f"✅ Anomaly detection testing completed successfully!")
    print(f"   • Tested {len(scenarios)} different scenarios")
    print(f"   • Used exact code from task specification")
    print(f"   • Results demonstrate anomaly detection capabilities")
    
    return 0

if __name__ == "__main__":
    exit(main())
