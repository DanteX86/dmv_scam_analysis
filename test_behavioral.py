import sys
import os
import json
from datetime import datetime
import pandas as pd

# Add scripts directory to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'scripts'))

from src.dmv_scam_analysis.analysis.behavioral import BehavioralAnalyzer

# Initialize analyzer
analyzer = BehavioralAnalyzer(output_dir="./analysis_output")

# Test messages with proper DataFrame structure
test_messages = [
    {
        'text': "URGENT: Your driver's license has been suspended. Click http://dmv-license-verify.tk to pay $299 reinstatement fee within 24 hours.",
        'source': 'sms',
        'timestamp': '2025-06-27T14:30:00Z',
        'is_from_me': 0,
        'readable_date': '2025-06-27T14:30:00Z'
    },
    {
        'text': "Your annual vehicle registration is due for renewal. Visit dmv.gov/renew or call 1-800-DMV-INFO.",
        'source': 'email',
        'timestamp': '2025-06-27T14:35:00Z',
        'is_from_me': 0,
        'readable_date': '2025-06-27T14:35:00Z'
    },
    {
        'text': "DMV Notice: License expiration detected. Renew now at https://gov-dmv-renewal.ml. Immediate action required to avoid suspension.",
        'source': 'sms',
        'timestamp': '2025-06-27T14:40:00Z',
        'is_from_me': 0,
        'readable_date': '2025-06-27T14:40:00Z'
    },
    {
        'text': "Reminder: Your vehicle registration expires next month. Renew online at www.dmv.gov or visit your local DMV office.",
        'source': 'email',
        'timestamp': '2025-06-27T14:45:00Z',
        'is_from_me': 0,
        'readable_date': '2025-06-27T14:45:00Z'
    },
    {
        'text': "FINAL WARNING: DMV records show unpaid violations. Pay $450 at dmv-pay-center.ga now to avoid license suspension and legal action.",
        'source': 'sms',
        'timestamp': '2025-06-27T14:50:00Z',
        'is_from_me': 0,
        'readable_date': '2025-06-27T14:50:00Z'
    }
]

# Create DataFrame
df = pd.DataFrame(test_messages)

print("\nAnalyzing messages...\n")

# Perform temporal pattern analysis
print("Temporal Pattern Analysis:")
temporal_analysis = analyzer.analyze_temporal_patterns(df)
if temporal_analysis:
    print("\nMessage Bursts:")
    bursts = temporal_analysis.get('burst_detection', {})
    print(f"Total bursts detected: {bursts.get('total_bursts', 0)}")
    
    print("\nTiming Anomalies:")
    anomalies = temporal_analysis.get('anomalous_timing', {})
    print(f"Anomaly score: {anomalies.get('anomaly_score', 0):.2f}")
    
    print("\nResponse Patterns:")
    responses = temporal_analysis.get('response_patterns', {})
    if isinstance(responses, dict):
        stats = responses.get('statistics', {})
        if stats:
            print(f"Average response time: {stats.get('average_response_time_seconds', 0):.2f} seconds")
            print(f"Total exchanges: {stats.get('total_exchanges', 0)}")

# Detect automation indicators
print("\nAutomation Analysis:")
automation_analysis = analyzer.detect_automation_indicators(df)
if automation_analysis:
    print(f"\nOverall automation score: {automation_analysis.get('overall_automation_score', 0):.2f}")
    
    print("\nTiming Regularity:")
    timing = automation_analysis.get('timing_regularity', {})
    if timing:
        print(f"Regularity score: {timing.get('regularity_score', 0):.2f}")
        print(f"Analysis: {timing.get('analysis', 'N/A')}")
    
    print("\nContent Patterns:")
    content = automation_analysis.get('content_similarity', {})
    if content:
        print(f"Similarity score: {content.get('similarity_score', 0):.2f}")
        print(f"Analysis: {content.get('analysis', 'N/A')}")
        print(f"Duplicate ratio: {content.get('duplicate_ratio', 0):.2f}")

# Generate behavioral report
report = analyzer.generate_behavioral_report("test_contact", temporal_analysis, automation_analysis)

# Print risk assessment
if 'risk_assessment' in report:
    risk = report['risk_assessment']
    print("\nRisk Assessment:")
    print(f"Risk Score: {risk.get('behavioral_risk_score', 0)}/100")
    print(f"Risk Level: {risk.get('risk_level', 'UNKNOWN')}")
    print("\nRisk Factors:")
    for factor in risk.get('risk_factors', []):
        print(f"  - {factor}")

# Print recommendations
if 'recommendations' in report:
    print("\nRecommendations:")
    for rec in report['recommendations']:
        print(f"[{rec['priority']}] {rec['recommendation']}")
        print(f"    Rationale: {rec['rationale']}")
