#!/usr/bin/env python3
"""
Test Anomaly Detection Capabilities
DMV Scam Analysis Project

Comprehensive testing of anomaly detection system with various scenarios:
- Normal communication patterns
- Burst messaging (many messages in short time)
- Unusual timing patterns (messages at odd hours)
- Statistical outliers in message length or content
"""

import pandas as pd
from datetime import datetime, timedelta
import numpy as np
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

def generate_normal_communication_pattern():
    """Generate normal business-hour communication pattern"""
    base_time = datetime(2024, 1, 15, 9, 0, 0)  # 9 AM start
    messages = []
    
    for i in range(5):
        # Normal business hours, reasonable intervals
        time_offset = i * 30  # 30 minutes apart
        timestamp = base_time + timedelta(minutes=time_offset)
        
        message = {
            "id": i + 1,
            "text": f"Your vehicle registration expires in {30-i*7} days. Please renew at your convenience.",
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "is_from_me": 0,
            "readable_date": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "handle_id": "dmv_official@ca.gov"
        }
        messages.append(message)
    
    return messages

def generate_burst_messaging_pattern():
    """Generate burst messaging pattern - many messages in short time"""
    base_time = datetime(2024, 1, 15, 14, 0, 0)
    messages = []
    
    # 10 messages within 5 minutes
    for i in range(10):
        time_offset = i * 30  # 30 seconds apart
        timestamp = base_time + timedelta(seconds=time_offset)
        
        message = {
            "id": i + 1,
            "text": f"URGENT MESSAGE #{i+1}: Your DMV account will be suspended! Act NOW!",
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "is_from_me": 0,
            "readable_date": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "handle_id": "urgent_dmv@suspicious.tk"
        }
        messages.append(message)
    
    return messages

def generate_unusual_timing_pattern():
    """Generate messages at unusual hours (midnight, 3 AM, etc.)"""
    messages = []
    unusual_hours = [0, 2, 3, 4, 23]  # Midnight, 2AM, 3AM, 4AM, 11PM
    
    for i, hour in enumerate(unusual_hours):
        timestamp = datetime(2024, 1, 15, hour, np.random.randint(0, 60), 0)
        
        message = {
            "id": i + 1,
            "text": "CRITICAL DMV ALERT: Immediate action required to avoid legal consequences!",
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "is_from_me": 0,
            "readable_date": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "handle_id": "night_dmv@scam.ml"
        }
        messages.append(message)
    
    return messages

def generate_statistical_outliers():
    """Generate messages with statistical outliers in length and content"""
    messages = []
    
    # Very short message
    messages.append({
        "id": 1,
        "text": "DMV!",
        "timestamp": "2024-01-15 10:00:00",
        "is_from_me": 0,
        "readable_date": "2024-01-15 10:00:00",
        "handle_id": "short@dmv.fake"
    })
    
    # Very long message (outlier)
    long_text = "URGENT NOTICE FROM DMV: " + "This is a very long scam message that contains repetitive content to make it appear legitimate while actually being fraudulent. " * 20
    messages.append({
        "id": 2,
        "text": long_text,
        "timestamp": "2024-01-15 10:01:00",
        "is_from_me": 0,
        "readable_date": "2024-01-15 10:01:00",
        "handle_id": "verbose@dmv.scam"
    })
    
    # Message with unusual character patterns
    messages.append({
        "id": 3,
        "text": "DMV ALERT!!!!!!!!!!!!!!!! YOUR LICENSE STATUS REQUIRES IMMEDIATE ATTENTION!!!!!!!!",
        "timestamp": "2024-01-15 10:02:00",
        "is_from_me": 0,
        "readable_date": "2024-01-15 10:02:00",
        "handle_id": "caps@dmv.fake"
    })
    
    # Message with suspicious URLs
    messages.append({
        "id": 4,
        "text": "Visit http://dmv-renewal.tk/verify http://dmv-check.ml/status http://dmv-alert.ga/urgent for immediate action",
        "timestamp": "2024-01-15 10:03:00",
        "is_from_me": 0,
        "readable_date": "2024-01-15 10:03:00",
        "handle_id": "links@dmv.suspicious"
    })
    
    return messages

def run_anomaly_test(test_name, messages, classifier):
    """Run anomaly detection test on a set of messages"""
    print("\n" + "="*60)
    print(f"Testing: {test_name}")
    print("="*60)
    
    # Convert to DataFrame
    df = pd.DataFrame(messages)
    
    # Display message details
    print(f"Messages count: {len(messages)}")
    if len(messages) > 0:
        timestamps = [msg['readable_date'] for msg in messages]
        print(f"Time range: {min(timestamps)} to {max(timestamps)}")
        
        # Show message lengths
        lengths = [len(msg['text']) for msg in messages]
        print(f"Message lengths - Min: {min(lengths)}, Max: {max(lengths)}, Avg: {np.mean(lengths):.1f}")
        
        # Show sample messages
        print("\nSample messages:")
        for i, msg in enumerate(messages[:3]):
            print(f"  {i+1}. [{msg['readable_date']}] {msg['text'][:80]}{'...' if len(msg['text']) > 80 else ''}")
    
    # Run anomaly detection
    try:
        anomaly_results = classifier.detect_anomalies(df)
        
        if 'error' in anomaly_results:
            print(f"❌ Error in anomaly detection: {anomaly_results['error']}")
            return None
        
        # Display results as requested in the task
        overall_assessment = anomaly_results.get('overall_assessment', {})
        anomaly_likelihood = overall_assessment.get('anomaly_likelihood', 0)
        primary_concerns = overall_assessment.get('primary_concerns', [])
        
        print("\n🔍 ANOMALY DETECTION RESULTS:")
        print(f"Anomaly likelihood: {anomaly_likelihood}%")
        print(f"Primary concerns: {primary_concerns}")
        
        # Additional detailed results
        iso_forest = anomaly_results.get('isolation_forest', {})
        statistical_outliers = anomaly_results.get('statistical_outliers', {})
        
        print("\n📊 Detailed Analysis:")
        print(f"  Isolation Forest - Anomaly detected: {iso_forest.get('is_anomaly', False)}")
        print(f"  Isolation Forest - Anomaly score: {iso_forest.get('anomaly_score', 0):.3f}")
        print(f"  Statistical outliers count: {statistical_outliers.get('outlier_count', 0)}")
        
        if statistical_outliers.get('outlier_features'):
            print("  Outlier features:")
            for feature in statistical_outliers['outlier_features'][:5]:  # Show top 5
                print(f"    - {feature['feature']}: z-score={feature['z_score']:.2f}, value={feature['value']:.2f}")
        
        return anomaly_results
        
    except Exception as e:
        print(f"❌ Exception during anomaly detection: {e}")
        import traceback
        traceback.print_exc()
        return None

def main():
    """Main function to run all anomaly detection tests"""
    print("🚀 Starting Comprehensive Anomaly Detection Testing")
    print("=" * 80)
    
    # Initialize the ML classifier
    try:
        classifier = MLThreatClassifier(output_dir="./test_output")
        print("✅ ML Threat Classifier initialized successfully")
    except Exception as e:
        print(f"❌ Failed to initialize classifier: {e}")
        return 1
    
    # Test scenarios
    test_scenarios = [
        ("Normal Communication Patterns", generate_normal_communication_pattern()),
        ("Burst Messaging (Many messages in short time)", generate_burst_messaging_pattern()),
        ("Unusual Timing Patterns (Messages at odd hours)", generate_unusual_timing_pattern()),
        ("Statistical Outliers in Message Length/Content", generate_statistical_outliers())
    ]
    
    # Store all results for comparison
    all_results = {}
    
    # Run each test scenario
    for test_name, messages in test_scenarios:
        result = run_anomaly_test(test_name, messages, classifier)
        if result:
            all_results[test_name] = result
    
    # Comparative analysis
    print("\n" + "="*80)
    print("COMPARATIVE ANALYSIS")
    print("="*80)
    
    print(f"{'Scenario':<45} {'Anomaly %':<12} {'Isolation Forest':<18} {'Outliers':<10}")
    print("-" * 85)
    
    for test_name, result in all_results.items():
        overall = result.get('overall_assessment', {})
        iso_forest = result.get('isolation_forest', {})
        outliers = result.get('statistical_outliers', {})
        
        anomaly_pct = overall.get('anomaly_likelihood', 0)
        is_anomaly = "✓" if iso_forest.get('is_anomaly', False) else "✗"
        outlier_count = outliers.get('outlier_count', 0)
        
        print(f"{test_name:<45} {anomaly_pct:<12}% {is_anomaly:<18} {outlier_count:<10}")
    
    # Summary and insights
    print("\n" + "="*80)
    print("SUMMARY AND INSIGHTS")
    print("="*80)
    
    if all_results:
        # Find highest and lowest anomaly scores
        anomaly_scores = {name: result.get('overall_assessment', {}).get('anomaly_likelihood', 0) 
                         for name, result in all_results.items()}
        
        highest_anomaly = max(anomaly_scores, key=anomaly_scores.get)
        lowest_anomaly = min(anomaly_scores, key=anomaly_scores.get)
        
        print(f"📈 Highest anomaly likelihood: {highest_anomaly} ({anomaly_scores[highest_anomaly]}%)")
        print(f"📉 Lowest anomaly likelihood: {lowest_anomaly} ({anomaly_scores[lowest_anomaly]}%)")
        
        # Common concerns
        all_concerns = []
        for result in all_results.values():
            concerns = result.get('overall_assessment', {}).get('primary_concerns', [])
            all_concerns.extend(concerns)
        
        if all_concerns:
            print("\n🔍 Most common concern types:")
            concern_types = {}
            for concern in all_concerns:
                concern_type = concern.split(':')[0] if ':' in concern else concern
                concern_types[concern_type] = concern_types.get(concern_type, 0) + 1
            
            for concern_type, count in sorted(concern_types.items(), key=lambda x: x[1], reverse=True):
                print(f"  - {concern_type}: {count} occurrences")
    
    print("\n✅ Anomaly detection testing completed successfully!")
    print("   All test scenarios executed and analyzed.")
    print("   Results saved to ./test_output/ directory.")
    
    return 0

if __name__ == "__main__":
    exit(main())
