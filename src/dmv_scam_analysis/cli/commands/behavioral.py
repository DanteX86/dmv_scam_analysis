#!/usr/bin/env python3
"""
Behavioral Analysis CLI
Provides command-line interface for behavioral analysis of messages
"""

import argparse
import json
import os
import sys
import warnings
from datetime import datetime
from typing import Any, Dict, List

import pandas as pd

from dmv_scam_analysis.analysis.behavioral import BehavioralAnalyzer

warnings.filterwarnings("ignore")


def analyze_messages(messages: List[Dict[str, str]], output_dir: str) -> Dict[str, Any]:
    """Analyze a list of messages"""
    # Create DataFrame
    df = pd.DataFrame(messages)

    # Initialize analyzer
    analyzer = BehavioralAnalyzer(output_dir=output_dir)

    # Perform analysis
    temporal_analysis = analyzer.analyze_temporal_patterns(df)
    automation_analysis = analyzer.detect_automation_indicators(df)

    # Generate report
    report = analyzer.generate_behavioral_report(
        "cli_analysis", temporal_analysis, automation_analysis
    )

    return {
        "temporal_analysis": temporal_analysis,
        "automation_analysis": automation_analysis,
        "report": report,
    }


def analyze_file(file_path: str, output_dir: str) -> Dict[str, Any]:
    """Analyze messages from a file"""
    # Load messages from file
    if file_path.endswith(".json"):
        with open(file_path, "r") as f:
            messages = json.load(f)
    elif file_path.endswith(".csv"):
        df = pd.read_csv(file_path)
        messages = df.to_dict("records")
    else:
        raise ValueError("Unsupported file format. Use .json or .csv")

    return analyze_messages(messages, output_dir)


def main() -> int:
    parser = argparse.ArgumentParser(description="Behavioral Analysis CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # analyze-file command
    file_parser = subparsers.add_parser(
        "analyze-file", help="Analyze messages from a file"
    )
    file_parser.add_argument("file", help="Path to message file (.json or .csv)")
    file_parser.add_argument(
        "--output-dir",
        default="./analysis_output",
        help="Output directory for analysis results",
    )

    # analyze-message command
    message_parser = subparsers.add_parser(
        "analyze-message", help="Analyze a single message"
    )
    message_parser.add_argument("message", help="Message text to analyze")
    message_parser.add_argument(
        "--source", default="cli", help="Message source (e.g., sms, email)"
    )
    message_parser.add_argument(
        "--output-dir",
        default="./analysis_output",
        help="Output directory for analysis results",
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    try:
        # Create output directory if it doesn't exist
        os.makedirs(args.output_dir, exist_ok=True)

        if args.command == "analyze-file":
            print(f"\nAnalyzing messages from: {args.file}")
            results = analyze_file(args.file, args.output_dir)

            print("\nAnalysis Results:")
            print("\nTemporal Analysis:")
            if results["temporal_analysis"]:
                bursts = results["temporal_analysis"].get("burst_detection", {})
                print(f"- Message bursts detected: {bursts.get('total_bursts', 0)}")

                anomalies = results["temporal_analysis"].get("anomalous_timing", {})
                print(
                    f"- Timing anomaly score: {anomalies.get('anomaly_score', 0):.2f}"
                )

            print("\nAutomation Analysis:")
            if results["automation_analysis"]:
                print(
                    f"- Overall automation score: {results['automation_analysis'].get('overall_automation_score', 0):.2f}"
                )

                timing = results["automation_analysis"].get("timing_regularity", {})
                if timing:
                    print(
                        f"- Timing regularity score: {timing.get('regularity_score', 0):.2f}"
                    )
                    print(f"- Analysis: {timing.get('analysis', 'N/A')}")

            if "report" in results and "risk_assessment" in results["report"]:
                risk = results["report"]["risk_assessment"]
                print(f"\nRisk Score: {risk.get('behavioral_risk_score', 0)}/100")
                print(f"Risk Level: {risk.get('risk_level', 'UNKNOWN')}")

                if risk.get("risk_factors"):
                    print("\nRisk Factors:")
                    for factor in risk["risk_factors"]:
                        print(f"- {factor}")

        elif args.command == "analyze-message":
            # Create test message
            message = {
                "text": args.message,
                "source": args.source,
                "timestamp": datetime.now().isoformat(),
                "is_from_me": 0,
                "readable_date": datetime.now().isoformat(),
            }

            print(f"\nAnalyzing message from {args.source}:")
            print(f"Message: {args.message}")

            results = analyze_messages([message], args.output_dir)

            if results["automation_analysis"]:
                print("\nAutomation Indicators:")
                print(
                    f"Overall score: {results['automation_analysis'].get('overall_automation_score', 0):.2f}"
                )

                content = results["automation_analysis"].get("content_similarity", {})
                if content:
                    print(f"Content analysis: {content.get('analysis', 'N/A')}")

            if "report" in results and "risk_assessment" in results["report"]:
                risk = results["report"]["risk_assessment"]
                print("\nRisk Assessment:")
                print(f"Score: {risk.get('behavioral_risk_score', 0)}/100")
                print(f"Level: {risk.get('risk_level', 'UNKNOWN')}")

                if "recommendations" in results["report"]:
                    print("\nRecommendations:")
                    for rec in results["report"]["recommendations"]:
                        print(f"[{rec['priority']}] {rec['recommendation']}")
                        print(f"    {rec['rationale']}")

    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
