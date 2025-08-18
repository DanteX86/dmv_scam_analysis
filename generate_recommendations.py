#!/usr/bin/env python3
"""
Recommendation Generation Script
Generates risk-based recommendations from analyzed data
"""

import sys
import json
import pandas as pd
from pathlib import Path

# Add src to path
sys.path.append('src')

from dmv_scam_analysis.analysis.risk_analyzer import RiskAnalyzer
from dmv_scam_analysis.analysis.temporal_analyzer import TemporalAnalyzer
from dmv_scam_analysis.analysis.automation_analyzer import AutomationAnalyzer

def generate_recommendations():
    """Generate recommendations from available test data or synthetic scenarios"""
    
    print("Generating risk-based recommendations...")
    print("=" * 40)
    print()
    
    # Create output directory
    Path("analysis_output").mkdir(exist_ok=True)
    
    # Initialize analyzers
    temporal_analyzer = TemporalAnalyzer()
    automation_analyzer = AutomationAnalyzer()
    risk_analyzer = RiskAnalyzer(output_dir='./analysis_output')
    
    # Try to find test data
    test_files = [
        "test_data/sample_messages.json",
        "test_data/scam_messages.json",
        "test_data/mixed_messages.json"
    ]
    
    data_found = False
    for test_file in test_files:
        if Path(test_file).exists():
            print(f"📊 Analyzing {test_file} for recommendations...")
            
            try:
                # Load and process data
                print("Loading test data...")
                with open(test_file, 'r') as f:
                    data = json.load(f)
                
                df = pd.DataFrame(data)
                df['datetime'] = pd.to_datetime(df['datetime'])
                
                # Perform analysis
                print("Performing temporal analysis...")
                temporal_analysis = temporal_analyzer.analyze_patterns(df)
                
                print("Performing automation analysis...")
                automation_analysis = automation_analyzer.detect_automation(df)
                
                print("Generating risk assessment and recommendations...")
                contact_id = f"analysis_{Path(test_file).stem}"
                report = risk_analyzer.analyze_risk(contact_id, temporal_analysis, automation_analysis)
                
                # Display recommendations
                print("\n🎯 Recommendations Generated:")
                print("=" * 30)
                
                recommendations = report.get('recommendations', [])
                if recommendations:
                    for rec in recommendations:
                        print(f"[{rec['priority']}] {rec['recommendation']}")
                        print(f"    Rationale: {rec['rationale']}")
                        print()
                else:
                    print("No specific recommendations generated for this dataset.")
                    print("This typically means the analyzed data shows low risk patterns.")
                
                # Show risk assessment
                risk_assessment = report.get('risk_assessment', {})
                print("\n📊 Risk Assessment:")
                print(f"   Risk Level: {risk_assessment.get('risk_level', 'UNKNOWN')}")
                print(f"   Risk Score: {risk_assessment.get('behavioral_risk_score', 0)}/100")
                
                automation = report.get('automation_indicators', {})
                automation_score = automation.get('overall_automation_score', 0)
                print(f"   Automation Likelihood: {automation_score:.2f} ({automation_score * 100:.1f}%)")
                
                print(f"\n📄 Full analysis report saved to: analysis_output/behavioral_analysis_{contact_id}.json")
                print(f"📄 Human-readable summary saved to: analysis_output/behavioral_summary_{contact_id}.txt")
                
                data_found = True
                break
                
            except Exception as e:
                print(f"⚠️ Error analyzing {test_file}: {str(e)}")
                continue
    
    if not data_found:
        print("⚠️ No test data found. Generating recommendations using synthetic high-risk scenario...")
        
        # Create synthetic high-risk scenario
        temporal_analysis = {
            'burst_detection': {'total_bursts': 5, 'max_burst_intensity': 10},
            'anomalous_timing': {'anomaly_score': 0.8},
            'hourly_distribution': {
                'distribution': {'2': 10, '3': 15, '4': 5, '14': 2},
            },
            'response_patterns': {
                'rapid_responses': [
                    {'time': '2024-01-01T02:00:00'},
                    {'time': '2024-01-01T02:01:00'},
                    {'time': '2024-01-01T02:02:00'},
                    {'time': '2024-01-01T02:03:00'}
                ]
            }
        }
        
        automation_analysis = {'overall_automation_score': 0.85}
        
        print("Generating recommendations for high-risk scenario...")
        report = risk_analyzer.analyze_risk('high_risk_demo', temporal_analysis, automation_analysis)
        
        print("\n🎯 Recommendations Generated:")
        print("=" * 30)
        
        for rec in report.get('recommendations', []):
            print(f"[{rec['priority']}] {rec['recommendation']}")
            print(f"    Rationale: {rec['rationale']}")
            print()
        
        # Show risk assessment
        risk_assessment = report.get('risk_assessment', {})
        print("\n📊 Risk Assessment:")
        print(f"   Risk Level: {risk_assessment.get('risk_level', 'UNKNOWN')}")
        print(f"   Risk Score: {risk_assessment.get('behavioral_risk_score', 0)}/100")
        
        print("\n📄 Full analysis report saved to: analysis_output/behavioral_analysis_high_risk_demo.json")
        print("📄 Human-readable summary saved to: analysis_output/behavioral_summary_high_risk_demo.txt")
    
    print("\n✅ Recommendations generation complete!")
    print("\n📂 Check the analysis_output/ directory for detailed reports:")
    print("   • JSON reports contain full analysis data")
    print("   • TXT summaries contain human-readable recommendations")

def test_recommendation_engine():
    """Test the recommendation engine with different risk scenarios"""
    
    print("🧪 Testing recommendation generation...")
    Path("analysis_output").mkdir(exist_ok=True)
    
    risk_analyzer = RiskAnalyzer(output_dir='./analysis_output')
    
    test_cases = [
        ('low_risk', {'burst_detection': {'total_bursts': 1}}, {'overall_automation_score': 0.2}),
        ('medium_risk', {'burst_detection': {'total_bursts': 3}, 'response_patterns': {'rapid_responses': [1,2,3,4]}}, {'overall_automation_score': 0.5}),
        ('high_risk', {'burst_detection': {'total_bursts': 5}, 'anomalous_timing': {'anomaly_score': 0.9}}, {'overall_automation_score': 0.8})
    ]
    
    for test_name, temporal, automation in test_cases:
        print(f'\n--- Testing {test_name} scenario ---')
        report = risk_analyzer.analyze_risk(f'test_{test_name}', temporal, automation)
        
        print(f'Risk Level: {report["risk_assessment"]["risk_level"]}')
        print(f'Risk Score: {report["risk_assessment"]["behavioral_risk_score"]}/100')
        print(f'Recommendations: {len(report["recommendations"])}')
        
        for rec in report['recommendations']:
            print(f'  - [{rec["priority"]}] {rec["recommendation"]}')
    
    print('\n✅ Recommendation testing complete!')

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        test_recommendation_engine()
    else:
        generate_recommendations()
