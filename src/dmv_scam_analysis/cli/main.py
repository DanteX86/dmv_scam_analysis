"""Command-line interface for DMV scam analysis tools."""

import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import click

from ..analysis.behavioral import BehavioralAnalyzer
from ..core.classifier import MLThreatClassifier as ThreatClassifier
from ..core.extractor import iMessageAnalyzer
from ..utils.config_manager import ConfigManager

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class AnalysisCLI:
    """CLI application class."""

    def __init__(self) -> None:
        """Initialize the CLI with necessary components"""
        self.config = ConfigManager()
        self.classifier = ThreatClassifier()
        self.analyzer = BehavioralAnalyzer()
        # Initialize extractor with default database path (can be overridden)
        default_db_path = self.config.get(
            "extractor.db_path", "~/Library/Messages/chat.db"
        )
        self.extractor = iMessageAnalyzer(default_db_path)


@click.group()
@click.option("--debug/--no-debug", default=False, help="Enable debug output")
@click.option("--config", type=click.Path(exists=True), help="Path to config file")
@click.pass_context
def cli(ctx: click.Context, debug: bool, config: Optional[str]) -> None:
    """DMV scam analysis toolkit.

    This tool provides various commands for analyzing potential DMV-related scams.
    """
    # Initialize logging
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Initialize CLI application
    ctx.obj = AnalysisCLI()
    if config:
        ctx.obj.config = ConfigManager(config)


@cli.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option(
    "--format", "-f", type=click.Choice(["json", "csv", "txt"]), default="json"
)
@click.pass_context
def analyze(
    ctx: click.Context, input_file: str, output: Optional[str], format: str
) -> None:
    """Analyze messages from input file for potential scams."""
    try:
        # Read input file
        messages = ctx.obj.extractor.read_messages(input_file)
        if not messages:
            click.echo(
                "No messages found in input file. "
                "Provide a JSON, CSV, or TXT file with message text."
            )
            sys.exit(1)

        # Perform analysis
        results = []
        for message in messages:
            # Get threat score
            threat_score = ctx.obj.classifier.predict([message["text"]])[0]

            # Get behavioral analysis
            behavior_analysis = ctx.obj.analyzer.analyze([message])

            # Combine results
            result = {
                "message_id": message.get("id", "unknown"),
                "timestamp": message.get("timestamp", datetime.now().isoformat()),
                "threat_score": float(threat_score),
                "risk_level": (
                    "high"
                    if threat_score > 0.7
                    else "medium"
                    if threat_score > 0.3
                    else "low"
                ),
                "indicators": behavior_analysis["indicators"],
                "confidence": behavior_analysis["confidence"],
                "analysis_id": behavior_analysis["analysis_id"],
            }
            results.append(result)

        # Export results
        if output:
            output_path = Path(output)
            if format == "json":
                with open(output_path, "w") as f:
                    json.dump(results, f, indent=2)
            elif format == "csv":
                import csv

                with open(output_path, "w", newline="") as f:
                    fieldnames = (
                        list(results[0].keys())
                        if results
                        else [
                            "message_id",
                            "timestamp",
                            "threat_score",
                            "risk_level",
                            "indicators",
                            "confidence",
                            "analysis_id",
                        ]
                    )
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    if results:
                        writer.writerows(results)
            else:  # txt
                with open(output_path, "w") as f:
                    if not results:
                        f.write("No analysis results.\n")
                    else:
                        for result in results:
                            f.write(f"Message ID: {result['message_id']}\n")
                            f.write(f"Timestamp: {result['timestamp']}\n")
                            f.write(f"Threat Score: {result['threat_score']:.2f}\n")
                            f.write(f"Risk Level: {result['risk_level']}\n")
                            f.write(f"Indicators: {', '.join(result['indicators'])}\n")
                            f.write(f"Confidence: {result['confidence']:.2f}\n")
                            f.write(f"Analysis ID: {result['analysis_id']}\n")
                            f.write("-" * 50 + "\n")
        else:
            # Print to stdout
            click.echo(json.dumps(results, indent=2))

    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}", exc_info=True)
        sys.exit(1)


@cli.command()
@click.argument("message_text")
@click.pass_context
def quick_check(ctx: click.Context, message_text: str) -> None:
    """Quickly analyze a single message."""
    try:
        # Get threat score
        threat_score = ctx.obj.classifier.predict([message_text])[0]

        # Get behavioral analysis
        analysis = ctx.obj.analyzer.analyze([{"text": message_text}])

        # Print results
        click.echo(f"Threat Score: {threat_score:.2f}")
        risk_level = (
            "high" if threat_score > 0.7 else "medium" if threat_score > 0.3 else "low"
        )
        click.echo(f"Risk Level: {risk_level}")
        click.echo(f"Indicators: {', '.join(analysis['indicators'])}")
        click.echo(f"Confidence: {analysis['confidence']:.2f}")

    except Exception as e:
        logger.error(f"Quick check failed: {str(e)}", exc_info=True)
        sys.exit(1)


@cli.command()
@click.argument("start_date", type=click.DateTime())
@click.argument("end_date", type=click.DateTime())
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.pass_context
def generate_report(
    ctx: click.Context, start_date: datetime, end_date: datetime, output: Optional[str]
) -> None:
    """Generate analysis report for a date range."""
    try:
        # Get statistics
        stats = ctx.obj.analyzer.get_statistics(start_date, end_date)

        # Generate report
        report = {
            "period": {"start": start_date.isoformat(), "end": end_date.isoformat()},
            "summary": {
                "total_analyzed": stats["total_analyzed"],
                "risk_distribution": stats["risk_distribution"],
                "top_indicators": stats.get("top_indicators", []),
            },
            "trends": {
                "daily_counts": stats.get("trend_data", []),
                "source_distribution": stats.get("source_distribution", {}),
            },
            "generated_at": datetime.now().isoformat(),
        }

        # Export or print report
        if output:
            with open(output, "w") as f:
                json.dump(report, f, indent=2)
        else:
            click.echo(json.dumps(report, indent=2))

    except Exception as e:
        logger.error(f"Report generation failed: {str(e)}", exc_info=True)
        sys.exit(1)


@cli.command()
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.pass_context
def model_info(ctx: click.Context, output: Optional[str]) -> None:
    """Display model information and statistics."""
    try:
        # Get model information
        info = {
            "classifier": {
                "version": ctx.obj.classifier.version,
                "last_updated": ctx.obj.classifier.last_updated,
                "model_type": ctx.obj.classifier.model_type,
                "feature_count": ctx.obj.classifier.feature_count,
            },
            "analyzer": {
                "version": ctx.obj.analyzer.version,
                "patterns": len(ctx.obj.analyzer.patterns),
                "indicators": ctx.obj.analyzer.available_indicators,
            },
            "performance": {
                "accuracy": ctx.obj.classifier.get_performance_metrics()["accuracy"],
                "precision": ctx.obj.classifier.get_performance_metrics()["precision"],
                "recall": ctx.obj.classifier.get_performance_metrics()["recall"],
                "f1_score": ctx.obj.classifier.get_performance_metrics()["f1_score"],
            },
        }

        # Export or print info
        if output:
            with open(output, "w") as f:
                json.dump(info, f, indent=2)
        else:
            click.echo(json.dumps(info, indent=2))

    except Exception as e:
        logger.error(f"Model info retrieval failed: {str(e)}", exc_info=True)
        sys.exit(1)


@cli.command("suggestions")
@click.argument("file", type=click.Path(exists=True, dir_okay=False, readable=True))
@click.option(
    "--export-json",
    "export_json_path",
    type=click.Path(dir_okay=False),
    help="Path to write full report JSON",
)
@click.option(
    "--export-csv",
    "export_csv_path",
    type=click.Path(dir_okay=False),
    help="Path to write recommendations CSV",
)
@click.option(
    "--export-yaml",
    "export_yaml_path",
    type=click.Path(dir_okay=False),
    help="Path to write full report YAML",
)
@click.option(
    "--keyword-threshold",
    type=int,
    default=3,
    show_default=True,
    help="Content keyword hit threshold for MEDIUM recommendation",
)
@click.option(
    "--payment-urgency-threshold",
    type=int,
    default=2,
    show_default=True,
    help="Payment/Urgency cue threshold for HIGH recommendation",
)
@click.pass_context
def suggestions(
    ctx: click.Context,
    file: str,
    export_json_path: Optional[str],
    export_csv_path: Optional[str],
    export_yaml_path: Optional[str],
    keyword_threshold: int,
    payment_urgency_threshold: int,
) -> None:
    """Generate suggestions (recommendations) from a JSON dataset with export options."""
    try:
        # Lazy imports to avoid affecting other commands
        import csv as _csv
        import re

        import pandas as pd

        from dmv_scam_analysis.analysis.automation_analyzer import AutomationAnalyzer
        from dmv_scam_analysis.analysis.risk_analyzer import RiskAnalyzer
        from dmv_scam_analysis.analysis.temporal_analyzer import TemporalAnalyzer

        # Optional YAML support
        from typing import Any as _Any
        _yaml: _Any = None
        try:
            import yaml as _yaml
        except Exception:
            _yaml = None

        def _compute_content_indicators(df: pd.DataFrame) -> dict:
            texts = df.get("text", pd.Series([], dtype=str)).astype(str).tolist()
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
            urgency_words = [
                "urgent",
                "immediate",
                "now",
                "last chance",
                "final notice",
            ]
            keyword_hits = url_count = payment_signals = urgency_signals = 0
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
                "thresholds": {
                    "keyword": keyword_threshold,
                    "payment_urgency": payment_urgency_threshold,
                },
            }

        # Load
        with open(file, "r", encoding="utf-8") as f:
            raw = json.load(f)
        records = (
            raw["messages"]
            if isinstance(raw, dict) and isinstance(raw.get("messages"), list)
            else raw
        )
        df = pd.DataFrame(records)
        if "readable_date" not in df.columns and "timestamp" in df.columns:
            parsed = pd.to_datetime(df["timestamp"], errors="coerce")
            df["readable_date"] = parsed.dt.strftime("%Y-%m-%d %H:%M:%S")
        if "is_from_me" not in df.columns:
            df["is_from_me"] = 0

        # Analyze
        temporal = TemporalAnalyzer().analyze_patterns(df) or {}
        auto = AutomationAnalyzer().detect_automation(df) or {}
        auto["content_indicators"] = _compute_content_indicators(df)
        contact_id = f"analysis_{Path(file).stem}"
        report = RiskAnalyzer(output_dir="./analysis_output").analyze_risk(
            contact_id, temporal, auto
        )

        # Export
        if export_json_path:
            with open(export_json_path, "w", encoding="utf-8") as jf:
                json.dump(report, jf, indent=2, ensure_ascii=False, default=str)
            click.echo(f"Wrote JSON: {export_json_path}")
        if export_csv_path:
            recs = report.get("recommendations", [])
            with open(export_csv_path, "w", encoding="utf-8", newline="") as cf:
                writer = _csv.DictWriter(
                    cf, fieldnames=["priority", "recommendation", "rationale"]
                )
                writer.writeheader()
                writer.writerows(recs)
            click.echo(f"Wrote CSV: {export_csv_path}")
        if export_yaml_path:
            if _yaml is None:
                click.echo("PyYAML not installed; skipping YAML export")
            else:
                # Convert to YAML-serializable native types
                # Optional numeric and pandas support
                from typing import Any as _Any
                _np: _Any = None
                try:
                    import numpy as _np
                except Exception:
                    _np = None
                try:
                    import pandas as _pd2
                except Exception:
                    _pd2 = None

                def _json_default(o: _Any) -> _Any:
                    if _np is not None and hasattr(_np, "generic") and isinstance(o, _np.generic):
                        return o.item()
                    if _pd2 is not None and hasattr(_pd2, "Timestamp") and isinstance(o, _pd2.Timestamp):
                        return o.isoformat()
                    return str(o)

                native_report = json.loads(json.dumps(report, default=_json_default))
                with open(export_yaml_path, "w", encoding="utf-8") as yf:
                    _yaml.safe_dump(
                        native_report, yf, sort_keys=False, allow_unicode=True
                    )
                click.echo(f"Wrote YAML: {export_yaml_path}")

        # Print summary
        click.echo(
            json.dumps(
                {
                    "file": file,
                    "risk_level": report.get("risk_assessment", {}).get("risk_level"),
                    "risk_score": report.get("risk_assessment", {}).get(
                        "behavioral_risk_score"
                    ),
                    "recommendation_count": len(report.get("recommendations", [])),
                },
                indent=2,
            )
        )

    except Exception as e:
        logger.error(f"Suggestions failed: {str(e)}", exc_info=True)
        sys.exit(1)


@cli.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option("--threshold", "-t", type=float, default=0.7, help="Confidence threshold")
@click.pass_context
def extract_iocs(ctx: click.Context, input_file: str, threshold: float) -> None:
    """Extract indicators of compromise from messages."""
    try:
        # Read input file
        messages = ctx.obj.extractor.read_messages(input_file)

        # Extract IOCs
        iocs = ctx.obj.analyzer.extract_iocs(messages, threshold)

        # Format results
        results = {
            "urls": iocs.get("urls", []),
            "phone_numbers": iocs.get("phone_numbers", []),
            "email_addresses": iocs.get("email_addresses", []),
            "domains": iocs.get("domains", []),
            "file_hashes": iocs.get("file_hashes", []),
        }

        # Print results
        click.echo(json.dumps(results, indent=2))
    except Exception as e:
        logger.error(f"IOC extraction failed: {str(e)}", exc_info=True)
        sys.exit(1)


@cli.command()
@click.option(
    "--db-path",
    "-d",
    type=click.Path(exists=True),
    default="~/Library/Messages/chat.db",
    help="Path to iMessage database",
)
@click.option("--contact", "-c", required=True, help="Contact identifier (phone/email)")
@click.option("--limit", "-l", type=int, help="Limit number of messages to export")
@click.option(
    "--output-dir",
    "-o",
    type=click.Path(),
    default="./analysis_output",
    help="Output directory for CSV file",
)
@click.option("--filename", "-f", type=str, help="Custom filename (without extension)")
@click.pass_context
def export_messages(
    ctx: click.Context,
    db_path: str,
    contact: str,
    limit: Optional[int],
    output_dir: str,
    filename: Optional[str],
) -> None:
    """Export iMessage messages for a contact to CSV."""
    try:
        # Expand paths
        db_path = os.path.expanduser(db_path)
        output_dir = os.path.expanduser(output_dir)

        # Initialize extractor with specified DB path
        extractor = iMessageAnalyzer(db_path=db_path, output_dir=output_dir)

        # Connect to database
        if not extractor.connect_database():
            click.echo("Failed to connect to iMessage database")
            sys.exit(1)

        # Extract messages
        df = extractor.extract_messages_by_contact(contact, limit)
        if df is None or df.empty:
            click.echo(f"No messages found for contact: {contact}")
            extractor.close_connection()
            sys.exit(1)

        # Generate filename
        if filename:
            csv_filename = f"{filename}.csv"
        else:
            import re
            from datetime import datetime

            sanitized = re.sub(r"[^\w\-@+]", "_", contact).strip("_")[:50]
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            csv_filename = f"messages_{sanitized}_{timestamp}.csv"

        # Export to CSV
        csv_path = os.path.join(output_dir, csv_filename)
        if extractor.export_messages_csv(df, csv_path):
            click.echo(f"Successfully exported {len(df)} messages to: {csv_path}")
        else:
            click.echo("Failed to export messages to CSV")
            extractor.close_connection()
            sys.exit(1)

        # Close connection
        extractor.close_connection()

    except Exception as e:
        logger.error(f"Export failed: {str(e)}", exc_info=True)
        sys.exit(1)


def main() -> None:
    """Main entry point for the CLI."""
    try:
        cli(obj=None)
    except Exception as e:
        logger.error(f"CLI execution failed: {str(e)}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
