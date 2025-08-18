#!/usr/bin/env python3
"""
Recommendation Generation Script
Generates risk-based recommendations from analyzed data
"""

import csv
import json
import re
import sys
from pathlib import Path
from typing import List, Optional

import pandas as pd

try:
    import yaml
except Exception:  # yaml is optional for exports; handled at runtime if missing
    yaml = None

# Add src to path
sys.path.append("src")

from dmv_scam_analysis.analysis.automation_analyzer import AutomationAnalyzer
from dmv_scam_analysis.analysis.risk_analyzer import RiskAnalyzer
from dmv_scam_analysis.analysis.temporal_analyzer import TemporalAnalyzer


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
    risk_analyzer = RiskAnalyzer(output_dir="./analysis_output")

    # Try to find test data
    test_files = [
        "test_data/sample_messages.json",
        "test_data/scam_messages.json",
        "test_data/mixed_messages.json",
    ]

    data_found = False
    for test_file in test_files:
        if Path(test_file).exists():
            print(f"📊 Analyzing {test_file} for recommendations...")

            try:
                # Load and process data
                print("Loading test data...")
                with open(test_file, "r") as f:
                    raw = json.load(f)

                # Normalize input schema: accept list or {"messages": [...]}
                if (
                    isinstance(raw, dict)
                    and "messages" in raw
                    and isinstance(raw["messages"], list)
                ):
                    records = raw["messages"]
                elif isinstance(raw, list):
                    records = raw
                else:
                    raise ValueError(
                        "Unsupported data format: expected list or {'messages': [...]}."
                    )

                df = pd.DataFrame(records)

                # Ensure a 'readable_date' column for TemporalAnalyzer
                # Prefer existing 'readable_date'; otherwise derive from 'timestamp'
                if "readable_date" not in df.columns:
                    if "timestamp" in df.columns:
                        # Parse various timestamp formats into a consistent string
                        parsed = pd.to_datetime(df["timestamp"], errors="coerce")
                        if parsed.isna().all():
                            raise ValueError(
                                "Could not parse any timestamps in 'timestamp' column."
                            )
                        df["readable_date"] = parsed.dt.strftime("%Y-%m-%d %H:%M:%S")
                    else:
                        raise ValueError(
                            "Missing 'readable_date' or 'timestamp' field in data."
                        )

                # Ensure 'is_from_me' exists; default to 0 (incoming) if absent
                if "is_from_me" not in df.columns:
                    df["is_from_me"] = 0

                # Perform analysis
                print("Performing temporal analysis...")
                temporal_analysis = temporal_analyzer.analyze_patterns(df)

                print("Performing automation analysis...")
                automation_analysis = automation_analyzer.detect_automation(df)

                # Content-based indicators
                content_indicators = _compute_content_indicators(df)
                if automation_analysis is None:
                    automation_analysis = {}
                automation_analysis["content_indicators"] = content_indicators

                print("Generating risk assessment and recommendations...")
                contact_id = f"analysis_{Path(test_file).stem}"
                report = risk_analyzer.analyze_risk(
                    contact_id, temporal_analysis, automation_analysis
                )

                # Display recommendations
                print("\n🎯 Recommendations Generated:")
                print("=" * 30)

                recommendations = report.get("recommendations", [])
                if recommendations:
                    for rec in recommendations:
                        print(f"[{rec['priority']}] {rec['recommendation']}")
                        print(f"    Rationale: {rec['rationale']}")
                        print()
                else:
                    print("No specific recommendations generated for this dataset.")
                    print(
                        "This typically means the analyzed data shows low risk patterns."
                    )

                # Show risk assessment
                risk_assessment = report.get("risk_assessment", {})
                print("\n📊 Risk Assessment:")
                print(f"   Risk Level: {risk_assessment.get('risk_level', 'UNKNOWN')}")
                print(
                    f"   Risk Score: {risk_assessment.get('behavioral_risk_score', 0)}/100"
                )

                automation = report.get("automation_indicators", {})
                automation_score = automation.get("overall_automation_score", 0)
                print(
                    f"   Automation Likelihood: {automation_score:.2f} ({automation_score * 100:.1f}%)"
                )

                print(
                    f"\n📄 Full analysis report saved to: analysis_output/behavioral_analysis_{contact_id}.json"
                )
                print(
                    f"📄 Human-readable summary saved to: analysis_output/behavioral_summary_{contact_id}.txt"
                )

                data_found = True

            except Exception as e:
                print(f"⚠️ Error analyzing {test_file}: {str(e)}")
                continue

    if not data_found:
        print(
            "⚠️ No test data found. Generating recommendations using synthetic high-risk scenario..."
        )

        # Create synthetic high-risk scenario
        temporal_analysis = {
            "burst_detection": {"total_bursts": 5, "max_burst_intensity": 10},
            "anomalous_timing": {"anomaly_score": 0.8},
            "hourly_distribution": {
                "distribution": {"2": 10, "3": 15, "4": 5, "14": 2},
            },
            "response_patterns": {
                "rapid_responses": [
                    {"time": "2024-01-01T02:00:00"},
                    {"time": "2024-01-01T02:01:00"},
                    {"time": "2024-01-01T02:02:00"},
                    {"time": "2024-01-01T02:03:00"},
                ]
            },
        }

        automation_analysis = {"overall_automation_score": 0.85}

        print("Generating recommendations for high-risk scenario...")
        report = risk_analyzer.analyze_risk(
            "high_risk_demo", temporal_analysis, automation_analysis
        )

        print("\n🎯 Recommendations Generated:")
        print("=" * 30)

        for rec in report.get("recommendations", []):
            print(f"[{rec['priority']}] {rec['recommendation']}")
            print(f"    Rationale: {rec['rationale']}")
            print()

        # Show risk assessment
        risk_assessment = report.get("risk_assessment", {})
        print("\n📊 Risk Assessment:")
        print(f"   Risk Level: {risk_assessment.get('risk_level', 'UNKNOWN')}")
        print(f"   Risk Score: {risk_assessment.get('behavioral_risk_score', 0)}/100")

        print(
            "\n📄 Full analysis report saved to: analysis_output/behavioral_analysis_high_risk_demo.json"
        )
        print(
            "📄 Human-readable summary saved to: analysis_output/behavioral_summary_high_risk_demo.txt"
        )

    print("\n✅ Recommendations generation complete!")
    print("\n📂 Check the analysis_output/ directory for detailed reports:")
    print("   • JSON reports contain full analysis data")
    print("   • TXT summaries contain human-readable recommendations")


def _compute_content_indicators(df: pd.DataFrame) -> dict:
    texts: List[str] = df.get("text", pd.Series([], dtype=str)).astype(str).tolist()
    url_pattern = re.compile(r"https?://|\b[a-z0-9.-]+\.[a-z]{2,}\b", re.I)
    keywords = [
        "dmv",
        "license",
        "suspend",
        "suspension",
        "renew",
        "verify",
        "verification",
        "refund",
        "pay",
        "payment",
        "ticket",
        "fine",
        "immediate",
        "urgent",
        "now",
        "account",
        "login",
        "password",
        "confirm",
        "update",
    ]
    payment_words = ["pay", "payment", "fine", "fee", "$", "usd"]
    urgency_words = ["urgent", "immediate", "now", "last chance", "final notice"]

    keyword_hits = 0
    url_count = 0
    payment_signals = 0
    urgency_signals = 0
    for t in texts:
        tl = t.lower()
        if url_pattern.search(t):
            url_count += 1
        if any(w in tl for w in keywords):
            keyword_hits += 1
        if any(w in tl for w in payment_words):
            payment_signals += 1
        if any(w in tl for w in urgency_words):
            urgency_signals += 1

    return {
        "keyword_hits": keyword_hits,
        "url_count": url_count,
        "payment_signals": payment_signals,
        "urgency_signals": urgency_signals,
        "keywords_scanned": keywords,
    }


def _export_outputs(
    report: dict,
    json_path: Optional[str],
    csv_path: Optional[str],
    yaml_path: Optional[str],
) -> None:
    if json_path:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"Wrote JSON: {json_path}")
    if csv_path:
        recs = report.get("recommendations", [])
        fieldnames = ["priority", "recommendation", "rationale"]
        with open(csv_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in recs:
                writer.writerow({k: r.get(k, "") for k in fieldnames})
        print(f"Wrote CSV: {csv_path}")
    if yaml_path:
        if yaml is None:
            print("PyYAML not installed; skipping YAML export")
        else:
            # Convert to YAML-serializable native types via JSON round-trip
            try:
                import numpy as _np  # optional
            except Exception:
                _np = None
            try:
                import pandas as _pd  # optional
            except Exception:
                _pd = None

            def _json_default(o):
                if _np is not None and isinstance(o, _np.generic):
                    return o.item()
                if _pd is not None:
                    try:
                        if isinstance(o, _pd.Timestamp):
                            return o.isoformat()
                    except Exception:
                        pass
                return str(o)

            native = json.loads(json.dumps(report, default=_json_default))
            with open(yaml_path, "w", encoding="utf-8") as f:
                yaml.safe_dump(native, f, sort_keys=False, allow_unicode=True)
            print(f"Wrote YAML: {yaml_path}")


def test_recommendation_engine():
    """Test the recommendation engine with different risk scenarios"""

    print("🧪 Testing recommendation generation...")
    Path("analysis_output").mkdir(exist_ok=True)

    risk_analyzer = RiskAnalyzer(output_dir="./analysis_output")

    test_cases = [
        (
            "low_risk",
            {"burst_detection": {"total_bursts": 1}},
            {"overall_automation_score": 0.2},
        ),
        (
            "medium_risk",
            {
                "burst_detection": {"total_bursts": 3},
                "response_patterns": {"rapid_responses": [1, 2, 3, 4]},
            },
            {"overall_automation_score": 0.5},
        ),
        (
            "high_risk",
            {
                "burst_detection": {"total_bursts": 5},
                "anomalous_timing": {"anomaly_score": 0.9},
            },
            {"overall_automation_score": 0.8},
        ),
    ]

    for test_name, temporal, automation in test_cases:
        print(f"\n--- Testing {test_name} scenario ---")
        report = risk_analyzer.analyze_risk(f"test_{test_name}", temporal, automation)

        print(f'Risk Level: {report["risk_assessment"]["risk_level"]}')
        print(f'Risk Score: {report["risk_assessment"]["behavioral_risk_score"]}/100')
        print(f'Recommendations: {len(report["recommendations"])}')

        for rec in report["recommendations"]:
            print(f'  - [{rec["priority"]}] {rec["recommendation"]}')

    print("\n✅ Recommendation testing complete!")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate recommendations with optional exports"
    )
    parser.add_argument("--file", help="Path to a specific dataset to analyze (JSON)")
    parser.add_argument(
        "--export-json", dest="export_json", help="Write full report JSON to this path"
    )
    parser.add_argument(
        "--export-csv", dest="export_csv", help="Write recommendations CSV to this path"
    )
    parser.add_argument(
        "--export-yaml", dest="export_yaml", help="Write full report YAML to this path"
    )
    parser.add_argument("test", nargs="?", help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.test == "test":
        test_recommendation_engine()
    elif args.file:
        # Single-file mode with exports
        Path("analysis_output").mkdir(exist_ok=True)
        temporal_analyzer = TemporalAnalyzer()
        automation_analyzer = AutomationAnalyzer()
        risk_analyzer = RiskAnalyzer(output_dir="./analysis_output")

        with open(args.file, "r") as f:
            raw = json.load(f)
        records = (
            raw["messages"]
            if isinstance(raw, dict) and isinstance(raw.get("messages"), list)
            else raw
        )
        df = pd.DataFrame(records)
        if "readable_date" not in df.columns:
            if "timestamp" in df.columns:
                parsed = pd.to_datetime(df["timestamp"], errors="coerce")
                df["readable_date"] = parsed.dt.strftime("%Y-%m-%d %H:%M:%S")
            else:
                raise SystemExit("Input missing 'timestamp' or 'readable_date'.")
        if "is_from_me" not in df.columns:
            df["is_from_me"] = 0

        temporal = temporal_analyzer.analyze_patterns(df)
        automation = automation_analyzer.detect_automation(df) or {}
        automation["content_indicators"] = _compute_content_indicators(df)
        contact_id = f"analysis_{Path(args.file).stem}"
        report = risk_analyzer.analyze_risk(contact_id, temporal, automation)

        # Exports
        _export_outputs(report, args.export_json, args.export_csv, args.export_yaml)
    else:
        generate_recommendations()
