#!/usr/bin/env python3
"""
Campaign Analysis Orchestrator
Framework for analyzing messaging-based scam campaigns.
"""

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

from ..analysis.automation_analyzer import AutomationAnalyzer
from ..analysis.risk_analyzer import RiskAnalyzer
from ..analysis.temporal_analyzer import TemporalAnalyzer


class CampaignAnalyzer:
    """Orchestrates analysis of messaging-based scam campaigns"""

    def __init__(
        self, campaign_name: str, output_dir: str = "./analysis_output"
    ) -> None:
        """
        Initialize campaign analyzer

        Args:
            campaign_name (str): Name/identifier for the campaign
            output_dir (str): Directory for analysis outputs
        """
        self.campaign_name = campaign_name
        self.output_dir = output_dir
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        # Initialize analyzers
        self.temporal_analyzer = TemporalAnalyzer()
        self.automation_analyzer = AutomationAnalyzer()
        self.risk_analyzer = RiskAnalyzer(output_dir=output_dir)

        # Analysis results
        self.results: Dict[str, Any] = {
            "campaign_metadata": {
                "name": campaign_name,
                "analysis_timestamp": datetime.now().isoformat(),
            },
            "contacts_analyzed": [],
            "campaign_stats": {},
            "high_risk_contacts": [],
            "automation_indicators": [],
        }

    def analyze_campaign(
        self, data_source: Any, campaign_type: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Analyze an entire messaging campaign

        Args:
            data_source: Path to data file or DataFrame with campaign data
            campaign_type (str, optional): Type of campaign (e.g., 'sms', 'email')

        Returns:
            dict: Campaign analysis results
        """
        try:
            # Load data if needed
            messages_df = self._load_data(data_source)

            # Update metadata
            metadata: Dict[str, Any] = self.results["campaign_metadata"]
            metadata.update(
                {
                    "campaign_type": campaign_type,
                    "total_messages": len(messages_df),
                    "date_range": {
                        "start": messages_df["datetime"].min().isoformat(),
                        "end": messages_df["datetime"].max().isoformat(),
                    },
                }
            )

            # Analyze each contact's messages
            for contact in messages_df["contact_id"].unique():
                contact_messages = messages_df[messages_df["contact_id"] == contact]
                contact_analysis = self._analyze_contact(contact, contact_messages)

                if contact_analysis:
                    contacts_analyzed: List[Dict[str, Any]] = self.results[
                        "contacts_analyzed"
                    ]
                    contacts_analyzed.append(
                        {
                            "contact_id": contact,
                            "risk_level": contact_analysis["risk_assessment"][
                                "risk_level"
                            ],
                            "automation_score": contact_analysis[
                                "automation_indicators"
                            ]["overall_automation_score"],
                        }
                    )

                    # Track high-risk contacts
                    if contact_analysis["risk_assessment"]["risk_level"] == "HIGH":
                        high_risk_contacts: List[Dict[str, Any]] = self.results[
                            "high_risk_contacts"
                        ]
                        high_risk_contacts.append(
                            {
                                "contact_id": contact,
                                "risk_score": contact_analysis["risk_assessment"][
                                    "behavioral_risk_score"
                                ],
                                "risk_factors": contact_analysis["risk_assessment"][
                                    "risk_factors"
                                ],
                            }
                        )

                    # Track automation indicators
                    if (
                        contact_analysis["automation_indicators"][
                            "overall_automation_score"
                        ]
                        > 0.7
                    ):
                        automation_indicators: List[Dict[str, Any]] = self.results[
                            "automation_indicators"
                        ]
                        automation_indicators.append(
                            {
                                "contact_id": contact,
                                "automation_score": contact_analysis[
                                    "automation_indicators"
                                ]["overall_automation_score"],
                                "indicators": contact_analysis["automation_indicators"],
                            }
                        )

            # Calculate campaign-wide statistics
            self._calculate_campaign_stats()

            # Generate campaign report
            self._generate_campaign_report()

            return self.results

        except Exception as e:
            print(f"❌ Campaign analysis failed: {str(e)}")
            return None

    def _load_data(self, data_source: Any) -> pd.DataFrame:
        """Load and prepare campaign data"""
        if isinstance(data_source, pd.DataFrame):
            df = data_source.copy()
        elif isinstance(data_source, str):
            if data_source.endswith(".json"):
                with open(data_source, "r") as f:
                    df = pd.DataFrame(json.load(f))
            else:
                df = pd.read_csv(data_source)
        else:
            raise ValueError("Data source must be DataFrame or file path")

        # Ensure required columns
        required_columns = ["datetime", "contact_id", "text", "is_from_me"]
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            raise ValueError(f"Missing required columns: {missing_columns}")

        # Convert datetime
        df["datetime"] = pd.to_datetime(df["datetime"])

        return df

    def _analyze_contact(
        self, contact_id: str, messages_df: pd.DataFrame
    ) -> Optional[Dict[str, Any]]:
        """Analyze messages from a single contact"""
        try:
            # Temporal analysis
            temporal_analysis = self.temporal_analyzer.analyze_patterns(messages_df)
            if temporal_analysis is None:
                return None

            # Automation detection
            automation_analysis = self.automation_analyzer.detect_automation(
                messages_df
            )
            if automation_analysis is None:
                return None

            # Risk assessment
            return self.risk_analyzer.analyze_risk(
                contact_id, temporal_analysis, automation_analysis
            )

        except Exception as e:
            print(f"⚠️ Analysis failed for contact {contact_id}: {str(e)}")
            return None

    def _calculate_campaign_stats(self) -> None:
        """Calculate campaign-wide statistics"""
        if not self.results["contacts_analyzed"]:
            return

        analyzed_contacts = len(self.results["contacts_analyzed"])
        high_risk_contacts = len(self.results["high_risk_contacts"])
        automated_contacts = len(self.results["automation_indicators"])

        self.results["campaign_stats"] = {
            "total_contacts_analyzed": analyzed_contacts,
            "high_risk_percentage": (high_risk_contacts / analyzed_contacts) * 100,
            "automated_percentage": (automated_contacts / analyzed_contacts) * 100,
            "risk_distribution": {
                "HIGH": len(
                    [
                        c
                        for c in self.results["contacts_analyzed"]
                        if c["risk_level"] == "HIGH"
                    ]
                ),
                "MEDIUM": len(
                    [
                        c
                        for c in self.results["contacts_analyzed"]
                        if c["risk_level"] == "MEDIUM"
                    ]
                ),
                "LOW": len(
                    [
                        c
                        for c in self.results["contacts_analyzed"]
                        if c["risk_level"] == "LOW"
                    ]
                ),
            },
        }

    def _generate_campaign_report(self) -> None:
        """Generate comprehensive campaign analysis report"""
        report_file = f"{self.output_dir}/campaign_analysis_{self.campaign_name}.json"
        summary_file = f"{self.output_dir}/campaign_summary_{self.campaign_name}.txt"

        # Save detailed report
        with open(report_file, "w") as f:
            json.dump(self.results, f, indent=2, default=str)

        # Generate summary
        with open(summary_file, "w") as f:
            f.write(f"Campaign Analysis Summary: {self.campaign_name}\n")
            f.write("=" * 50 + "\n\n")

            # Campaign overview
            f.write("Campaign Overview\n")
            f.write("-" * 20 + "\n")
            f.write(
                f"Analysis Date: {self.results['campaign_metadata']['analysis_timestamp']}\n"
            )
            campaign_type = self.results["campaign_metadata"].get(
                "campaign_type", "Unknown"
            )
            f.write(f"Campaign Type: {campaign_type}\n")
            f.write(
                f"Total Messages: {self.results['campaign_metadata']['total_messages']}\n"
            )
            f.write(
                f"Date Range: {self.results['campaign_metadata']['date_range']['start']} to "
            )
            f.write(f"{self.results['campaign_metadata']['date_range']['end']}\n\n")

            # Key statistics
            stats: Dict[str, Any] = self.results["campaign_stats"]
            f.write("Key Statistics\n")
            f.write("-" * 20 + "\n")
            f.write(f"Contacts Analyzed: {stats['total_contacts_analyzed']}\n")
            f.write(f"High Risk Contacts: {stats['high_risk_percentage']:.1f}%\n")
            f.write(f"Automated Behavior: {stats['automated_percentage']:.1f}%\n\n")

            # Risk distribution
            f.write("Risk Distribution\n")
            f.write("-" * 20 + "\n")
            for level, count in stats["risk_distribution"].items():
                percentage = (count / stats["total_contacts_analyzed"]) * 100
                f.write(f"{level}: {count} contacts ({percentage:.1f}%)\n")

            # High risk contacts
            if self.results["high_risk_contacts"]:
                f.write("\nHigh Risk Contacts\n")
                f.write("-" * 20 + "\n")
                for contact in self.results["high_risk_contacts"]:
                    f.write(f"\nContact: {contact['contact_id']}\n")
                    f.write(f"Risk Score: {contact['risk_score']}/100\n")
                    f.write("Risk Factors:\n")
                    for factor in contact["risk_factors"]:
                        f.write(f"  • {factor}\n")

            # Automation indicators
            if self.results["automation_indicators"]:
                f.write("\nAutomation Indicators\n")
                f.write("-" * 20 + "\n")
                for contact in self.results["automation_indicators"]:
                    f.write(f"\nContact: {contact['contact_id']}\n")
                    f.write(f"Automation Score: {contact['automation_score']:.2f}\n")

        print(f"✓ Campaign analysis report saved: {report_file}")
        print(f"✓ Campaign summary saved: {summary_file}")


def configure_input_output(
    data_source: Any,
    output_dir: str,
    input_format: Optional[str] = None,
    output_format: str = "json",
) -> Tuple[pd.DataFrame, str, str]:
    """
    Configure input data source and output parameters

    Args:
        data_source: Path or DataFrame for source data
        output_dir: Directory for storing outputs
        input_format: Expected format of input data (csv or json)
        output_format: Format for analysis outputs (json or txt)

    Returns:
        tuple: Configured DataFrame and output paths
    """

    def load_data(file_path: str, fmt: Optional[str] = None) -> pd.DataFrame:
        if fmt == "json" or file_path.endswith(".json"):
            with open(file_path, "r") as f:
                return pd.DataFrame(json.load(f))
        elif fmt == "csv" or file_path.endswith(".csv"):
            return pd.read_csv(file_path)
        else:
            raise ValueError("Unsupported input format")

    if isinstance(data_source, pd.DataFrame):
        df = data_source.copy()
    elif isinstance(data_source, str):
        df = load_data(data_source, input_format)
    else:
        raise ValueError("Data source must be DataFrame or valid file path")

    output_dir_path = Path(output_dir)
    output_dir_path.mkdir(parents=True, exist_ok=True)

    output_file_base = output_dir_path / "campaign_analysis"
    if output_format == "json":
        return df, f"{output_file_base}.json", f"{output_file_base}_summary.txt"
    elif output_format == "txt":
        return df, f"{output_file_base}.txt", f"{output_file_base}_summary.txt"
    else:
        raise ValueError("Unsupported output format")


def main() -> int:
    """Main execution function"""
    parser = argparse.ArgumentParser(
        description="Campaign Analysis Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example usage:
  %(prog)s --input campaign_data.csv --name "DMV_Scam_2025" --type sms
  %(prog)s --input messages.json --name "Email_Campaign_01" --type email
        """,
    )

    parser.add_argument(
        "--input", required=True, help="Path to campaign data file (JSON or CSV)"
    )
    parser.add_argument("--name", required=True, help="Campaign name/identifier")
    parser.add_argument("--type", help="Campaign type (e.g., sms, email)", default=None)
    parser.add_argument(
        "--input-format", choices=["csv", "json"], help="Specify input file format"
    )
    parser.add_argument(
        "--output-format",
        choices=["json", "txt"],
        default="json",
        help="Specify output file format",
    )
    parser.add_argument(
        "--output-dir",
        default="./analysis_output",
        help="Output directory for analysis results",
    )

    args = parser.parse_args()

    try:
        input_df, report_path, summary_path = configure_input_output(
            data_source=args.input,
            output_dir=args.output_dir,
            input_format=args.input_format,
            output_format=args.output_format,
        )

        analyzer = CampaignAnalyzer(campaign_name=args.name, output_dir=args.output_dir)

        results = analyzer.analyze_campaign(
            data_source=input_df, campaign_type=args.type
        )

        if results:
            stats = results["campaign_stats"]
            print(f"\n✓ Campaign analysis complete: {args.name}")
            print(f"✓ Contacts analyzed: {stats['total_contacts_analyzed']}")
            print(f"✓ High risk contacts: {stats['high_risk_percentage']:.1f}%")
            print(f"✓ Automated behavior: {stats['automated_percentage']:.1f}%")
            return 0
        else:
            print("❌ Campaign analysis failed")
            return 1

    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return 1


if __name__ == "__main__":
    exit(main())
