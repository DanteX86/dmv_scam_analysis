#!/usr/bin/env python3
"""
Test Runner for DMV Scam Analysis Tools
"""

import json
import os
import sys
from datetime import datetime

import pandas as pd

from scripts.behavioral_analyzer import BehavioralAnalyzer
from scripts.ml_threat_classifier import MLThreatClassifier

# Set up paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA_DIR = os.path.join(BASE_DIR, "test_data")
TEST_OUTPUT_DIR = os.path.join(BASE_DIR, "test_output")
TEST_SUITES_DIR = os.path.join(TEST_DATA_DIR, "test_suites")


class TestError(Exception):
    """Custom exception for test failures"""

    pass


def validate_dataframe(df, required_columns=None):
    """Validate DataFrame structure and content"""
    if required_columns is None:
        required_columns = [
            "text",
            "source",
            "timestamp",
            "is_from_me",
            "readable_date",
        ]

    # Check required columns
    missing_columns = [col for col in required_columns if col not in df.columns]
    if missing_columns:
        raise TestError(f"Missing required columns: {missing_columns}")

    # Check for null values
    null_counts = df[required_columns].isnull().sum()
    if null_counts.sum() > 0:
        print("Warning: Found null values:")
        for col, count in null_counts.items():
            if count > 0:
                print(f"  - {col}: {count} null values")

    # Validate data types
    try:
        df["datetime"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df["is_from_me"] = pd.to_numeric(df["is_from_me"], errors="coerce")
    except Exception as e:
        raise TestError(f"Data type validation failed: {str(e)}")

    return df


def run_timing_pattern_tests():
    """Test timing pattern detection"""
    print("\n=== Testing Timing Pattern Detection ===")

    # Load test data
    with open(os.path.join(TEST_SUITES_DIR, "timing_patterns.json"), "r") as f:
        data = json.load(f)
    df = pd.DataFrame(data)
    df["datetime"] = pd.to_datetime(df["timestamp"])

    # Initialize analyzer
    analyzer = BehavioralAnalyzer(output_dir=TEST_OUTPUT_DIR)

    # Analyze temporal patterns
    temporal_analysis = analyzer.analyze_temporal_patterns(df)

    # Verify burst detection
    bursts = temporal_analysis["burst_detection"]
    print("\nBurst Detection:")
    print(f"Total bursts: {bursts['total_bursts']}")
    print(f"Max burst intensity: {bursts['max_burst_intensity']}")

    # Verify timing anomalies
    anomalies = temporal_analysis["anomalous_timing"]
    print("\nTiming Anomalies:")
    print(f"Anomaly score: {anomalies['anomaly_score']:.2f}")
    print(f"Number of anomalies: {len(anomalies['anomalies'])}")


def run_conversation_pattern_tests():
    """Test conversation pattern detection"""
    print("\n=== Testing Conversation Pattern Detection ===")

    # Load test data
    with open(os.path.join(TEST_SUITES_DIR, "conversation_patterns.json"), "r") as f:
        data = json.load(f)
    df = pd.DataFrame(data)
    df["datetime"] = pd.to_datetime(df["timestamp"])

    # Initialize analyzer
    analyzer = BehavioralAnalyzer(output_dir=TEST_OUTPUT_DIR)

    # Analyze automation indicators
    automation_analysis = analyzer.detect_automation_indicators(df)

    # Print results
    print("\nAutomation Analysis:")
    print(
        f"Overall automation score: {automation_analysis['overall_automation_score']:.2f}"
    )
    print(
        f"Content similarity score: {automation_analysis['content_similarity']['similarity_score']:.2f}"
    )
    print(
        f"Response predictability: {automation_analysis['response_predictability']['predictability_score']:.2f}"
    )


def run_comprehensive_tests():
    """Run comprehensive analysis tests"""
    print("\n=== Running Comprehensive Analysis ===")

    # Load test data
    with open(os.path.join(TEST_DATA_DIR, "comprehensive_test.json"), "r") as f:
        data = json.load(f)
    df = pd.DataFrame(data)
    df["datetime"] = pd.to_datetime(df["timestamp"])

    # Initialize analyzers
    behavioral = BehavioralAnalyzer(output_dir=TEST_OUTPUT_DIR)
    classifier = MLThreatClassifier(output_dir=TEST_OUTPUT_DIR)

    # Run behavioral analysis
    temporal = behavioral.analyze_temporal_patterns(df)
    automation = behavioral.detect_automation_indicators(df)

    # Generate report
    report = behavioral.generate_behavioral_report(
        "comprehensive_test", temporal, automation
    )

    # Print summary
    print("\nBehavioral Analysis Results:")
    print(f"Risk Score: {report['risk_assessment']['behavioral_risk_score']}/100")
    print(f"Risk Level: {report['risk_assessment']['risk_level']}")

    if report["risk_assessment"]["risk_factors"]:
        print("\nRisk Factors:")
        for factor in report["risk_assessment"]["risk_factors"]:
            print(f"- {factor}")


def main():
    """Main test execution function"""
    # Create test output directory
    os.makedirs(TEST_OUTPUT_DIR, exist_ok=True)

    print("Starting DMV Scam Analysis Tests")
    print("================================")
    print(f"Test Run: {datetime.now().isoformat()}")

    try:
        # Run all test suites
        run_timing_pattern_tests()
        run_conversation_pattern_tests()
        run_comprehensive_tests()

        print("\n✓ All tests completed successfully")
        return 0

    except Exception as e:
        print(f"\n❌ Test execution failed: {str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
