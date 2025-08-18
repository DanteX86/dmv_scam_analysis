#!/usr/bin/env python3
"""Debug CLI for DMV scam analysis system."""
import json
import os
import sys
from datetime import datetime
from typing import Any, Dict, List

import click
import pandas as pd
from behavioral_analyzer import BehavioralAnalyzer
from ml_threat_classifier import MLThreatClassifier
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


class DebugContext:
    """Debug context maintaining state across commands."""

    def __init__(self) -> None:
        self.classifier = MLThreatClassifier(output_dir=".")
        self.analyzer = BehavioralAnalyzer()
        self.current_data = None
        self.current_features = None
        self.last_prediction = None
        self.debug_log: List[Dict[str, Any]] = []

    def log(self, message: str, level: str = "INFO") -> None:
        """Add message to debug log."""
        timestamp = datetime.now().isoformat()
        self.debug_log.append(
            {"timestamp": timestamp, "level": level, "message": message}
        )


pass_debug = click.make_pass_decorator(DebugContext, ensure=True)


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """Debug interface for DMV scam analysis system."""
    ctx.obj = DebugContext()
    ctx.obj.verbose = verbose
    if verbose:
        console.print("[yellow]Debug mode enabled[/yellow]")


@cli.command()
@click.argument("message")
@pass_debug
def analyze_message(ctx: DebugContext, message: str) -> None:
    """Debug analysis of a single message."""
    console.print("\n[bold blue]Analyzing Message[/bold blue]")
    console.print(Panel(message, title="Input Message"))

    # Create DataFrame
    df = pd.DataFrame(
        [
            {
                "text": message,
                "source": "debug",
                "timestamp": datetime.now().isoformat(),
                "is_from_me": 0,
            }
        ]
    )
    ctx.current_data = df

    # Extract features
    console.print("\n[bold green]Extracting Features[/bold green]")
    features = ctx.classifier.extract_ml_features(df)
    if features:
        ctx.current_features = features

        # Display features
        table = Table(title="Extracted Features")
        table.add_column("Feature", style="cyan")
        table.add_column("Value", style="magenta")

        for name, value in features["features"].iloc[0].items():
            table.add_row(
                name, f"{value:.4f}" if isinstance(value, float) else str(value)
            )

        console.print(table)
    else:
        console.print("[red]Feature extraction failed[/red]")
        return

    # Make prediction
    console.print("\n[bold green]Making Prediction[/bold green]")
    prediction = ctx.classifier.predict_threat_classification(df)
    ctx.last_prediction = prediction

    if isinstance(prediction, dict) and "predictions" in prediction:
        table = Table(title="Prediction Results")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="magenta")

        if "predictions" in prediction:
            table.add_row("Classification", str(prediction["predictions"][0]))
        if "max_threat_probability" in prediction:
            table.add_row(
                "Threat Probability", f"{prediction['max_threat_probability']:.2f}"
            )
        if "threat_risk_level" in prediction:
            table.add_row("Risk Level", prediction["threat_risk_level"])

        console.print(table)
    else:
        console.print("[red]Prediction failed[/red]")

    # Behavioral analysis
    console.print("\n[bold green]Behavioral Analysis[/bold green]")
    behavior = ctx.analyzer.analyze([{"text": message}])

    table = Table(title="Behavioral Analysis")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="magenta")

    table.add_row("Confidence", f"{behavior['confidence']:.2f}")
    table.add_row("Indicators", ", ".join(behavior["indicators"]))

    console.print(table)


@cli.command()
@click.argument("file_path", type=click.Path(exists=True))
@pass_debug
def analyze_file(ctx: DebugContext, file_path: str) -> None:
    """Debug analysis of messages from a file."""
    console.print(f"\n[bold blue]Analyzing File: {file_path}[/bold blue]")

    # Load data
    try:
        if file_path.endswith(".json"):
            with open(file_path) as f:
                data = json.load(f)
                if isinstance(data, list):
                    df = pd.DataFrame(data)
                elif isinstance(data, dict) and "messages" in data:
                    df = pd.DataFrame(data["messages"])
                else:
                    df = pd.DataFrame([data])
        elif file_path.endswith(".csv"):
            df = pd.read_csv(file_path)
        else:
            console.print("[red]Unsupported file format. Use .json or .csv[/red]")
            return
    except Exception as e:
        console.print(f"[red]Error loading file: {str(e)}[/red]")
        return

    ctx.current_data = df
    console.print(f"\nLoaded {len(df)} messages")

    # Analyze each message
    for idx, row in df.iterrows():
        console.print(f"\n[bold cyan]Message {idx + 1}[/bold cyan]")
        console.print(Panel(row["text"], title=f"Message {idx + 1}"))

        # Create single message DataFrame
        message_df = pd.DataFrame([row])

        # Extract features
        features = ctx.classifier.extract_ml_features(message_df)
        if features:
            feature_table = Table(title="Top Features")
            feature_table.add_column("Feature", style="cyan")
            feature_table.add_column("Value", style="magenta")

            # Show top 5 features
            for name, value in list(features["features"].iloc[0].items())[:5]:
                feature_table.add_row(
                    name, f"{value:.4f}" if isinstance(value, float) else str(value)
                )

            console.print(feature_table)

        # Make prediction
        prediction = ctx.classifier.predict_threat_classification(message_df)
        if isinstance(prediction, dict) and "predictions" in prediction:
            pred_table = Table(title="Prediction")
            pred_table.add_column("Metric", style="cyan")
            pred_table.add_column("Value", style="magenta")

            if "predictions" in prediction:
                pred_table.add_row("Classification", str(prediction["predictions"][0]))
            if "max_threat_probability" in prediction:
                pred_table.add_row(
                    "Threat Probability", f"{prediction['max_threat_probability']:.2f}"
                )
            if "threat_risk_level" in prediction:
                pred_table.add_row("Risk Level", prediction["threat_risk_level"])

            console.print(pred_table)


@cli.command()
@pass_debug
def inspect_model(ctx: DebugContext) -> None:
    """Debug inspection of the ML model."""
    console.print("\n[bold blue]Model Inspection[/bold blue]")

    # Get model information
    if (
        hasattr(ctx.classifier, "models")
        and "threat_classifier" in ctx.classifier.models
    ):
        model = ctx.classifier.models["threat_classifier"]

        # Model metadata
        meta_table = Table(title="Model Metadata")
        meta_table.add_column("Attribute", style="cyan")
        meta_table.add_column("Value", style="magenta")

        meta_table.add_row("Type", model.__class__.__name__)
        if hasattr(model, "n_features_in_"):
            meta_table.add_row("Number of Features", str(model.n_features_in_))
        if hasattr(model, "n_classes_"):
            meta_table.add_row("Number of Classes", str(model.n_classes_))

        console.print(meta_table)

        # Feature importance if available
        if hasattr(model, "feature_importances_"):
            importance_table = Table(title="Top Feature Importance")
            importance_table.add_column("Feature", style="cyan")
            importance_table.add_column("Importance", style="magenta")

            # Get feature names
            feature_names = (
                ctx.current_features["feature_names"]
                if ctx.current_features
                else [f"feature_{i}" for i in range(len(model.feature_importances_))]
            )

            # Sort and display top 10 features
            importances = list(zip(feature_names, model.feature_importances_))
            importances.sort(key=lambda x: x[1], reverse=True)

            for name, importance in importances[:10]:
                importance_table.add_row(name, f"{importance:.4f}")

            console.print(importance_table)
    else:
        console.print("[yellow]Model not trained yet[/yellow]")


@cli.command()
@click.argument("message")
@pass_debug
def debug_features(ctx: DebugContext, message: str) -> None:
    """Debug feature extraction for a message."""
    console.print("\n[bold blue]Feature Extraction Debug[/bold blue]")
    console.print(Panel(message, title="Input Message"))

    # Create DataFrame
    df = pd.DataFrame(
        [
            {
                "text": message,
                "source": "debug",
                "timestamp": datetime.now().isoformat(),
                "is_from_me": 0,
            }
        ]
    )

    # Extract features with verbose output
    console.print("\n[bold green]Text Features[/bold green]")
    text_features = ctx.classifier._extract_text_features(df)
    text_table = Table(title="Text Features")
    text_table.add_column("Feature", style="cyan")
    text_table.add_column("Value", style="magenta")

    for name, value in text_features.items():
        text_table.add_row(
            name, f"{value:.4f}" if isinstance(value, float) else str(value)
        )

    console.print(text_table)

    console.print("\n[bold green]Behavioral Features[/bold green]")
    behavioral_features = ctx.classifier._extract_behavioral_features(df)
    behavioral_table = Table(title="Behavioral Features")
    behavioral_table.add_column("Feature", style="cyan")
    behavioral_table.add_column("Value", style="magenta")

    for name, value in behavioral_features.items():
        behavioral_table.add_row(
            name, f"{value:.4f}" if isinstance(value, float) else str(value)
        )

    console.print(behavioral_table)

    console.print("\n[bold green]Statistical Features[/bold green]")
    statistical_features = ctx.classifier._extract_statistical_features(df)
    statistical_table = Table(title="Statistical Features")
    statistical_table.add_column("Feature", style="cyan")
    statistical_table.add_column("Value", style="magenta")

    for name, value in statistical_features.items():
        statistical_table.add_row(
            name, f"{value:.4f}" if isinstance(value, float) else str(value)
        )

    console.print(statistical_table)


@cli.command()
@click.argument("message")
@pass_debug
def explain_prediction(ctx: DebugContext, message: str) -> None:
    """Debug explanation of prediction for a message."""
    console.print("\n[bold blue]Prediction Explanation[/bold blue]")
    console.print(Panel(message, title="Input Message"))

    # Create DataFrame
    df = pd.DataFrame(
        [
            {
                "text": message,
                "source": "debug",
                "timestamp": datetime.now().isoformat(),
                "is_from_me": 0,
            }
        ]
    )

    # Extract features
    features = ctx.classifier.extract_ml_features(df)
    if not features:
        console.print("[red]Feature extraction failed[/red]")
        return

    # Make prediction
    prediction = ctx.classifier.predict_threat_classification(df)
    if not isinstance(prediction, dict) or "predictions" not in prediction:
        console.print("[red]Prediction failed[/red]")
        return

    # Display prediction
    console.print("\n[bold green]Prediction Details[/bold green]")
    pred_table = Table(title="Prediction Results")
    pred_table.add_column("Metric", style="cyan")
    pred_table.add_column("Value", style="magenta")

    if "predictions" in prediction:
        pred_table.add_row("Classification", str(prediction["predictions"][0]))
    if "max_threat_probability" in prediction:
        pred_table.add_row(
            "Threat Probability", f"{prediction['max_threat_probability']:.2f}"
        )
    if "threat_risk_level" in prediction:
        pred_table.add_row("Risk Level", prediction["threat_risk_level"])

    console.print(pred_table)

    # Feature contribution analysis
    if hasattr(ctx.classifier.models["threat_classifier"], "feature_importances_"):
        console.print("\n[bold green]Feature Contributions[/bold green]")

        # Get feature importance
        importances = ctx.classifier.models["threat_classifier"].feature_importances_
        feature_names = features["feature_names"]

        # Calculate feature contributions
        contributions = []
        feature_values = features["features"].iloc[0]

        for name, importance, value in zip(feature_names, importances, feature_values):
            contribution = importance * value
            contributions.append((name, importance, value, contribution))

        # Sort by absolute contribution
        contributions.sort(key=lambda x: abs(x[3]), reverse=True)

        # Display top contributing features
        contrib_table = Table(title="Top Contributing Features")
        contrib_table.add_column("Feature", style="cyan")
        contrib_table.add_column("Importance", style="magenta")
        contrib_table.add_column("Value", style="blue")
        contrib_table.add_column("Contribution", style="green")

        for name, importance, value, contribution in contributions[:10]:
            contrib_table.add_row(
                name,
                f"{importance:.4f}",
                f"{value:.4f}" if isinstance(value, float) else str(value),
                f"{contribution:.4f}",
            )

        console.print(contrib_table)


@cli.command()
@pass_debug
def show_log(ctx: DebugContext) -> None:
    """Show debug log."""
    console.print("\n[bold blue]Debug Log[/bold blue]")

    log_table = Table(title="Debug Log")
    log_table.add_column("Timestamp", style="cyan")
    log_table.add_column("Level", style="magenta")
    log_table.add_column("Message", style="white")

    for entry in ctx.debug_log:
        log_table.add_row(entry["timestamp"], entry["level"], entry["message"])

    console.print(log_table)


@cli.command()
@pass_debug
def system_info(ctx: DebugContext) -> None:
    """Show system information and dependencies."""
    console.print("\n[bold blue]System Information[/bold blue]")

    # System info
    sys_table = Table(title="System Information")
    sys_table.add_column("Component", style="cyan")
    sys_table.add_column("Value", style="magenta")

    sys_table.add_row("Python Version", sys.version.split()[0])
    sys_table.add_row("Operating System", os.name)
    sys_table.add_row("Platform", sys.platform)
    sys_table.add_row("Working Directory", os.getcwd())

    console.print(sys_table)

    # Dependencies
    dep_table = Table(title="Key Dependencies")
    dep_table.add_column("Package", style="cyan")
    dep_table.add_column("Version", style="magenta")

    import numpy as np
    import pandas as pd
    import sklearn

    dep_table.add_row("pandas", pd.__version__)
    dep_table.add_row("numpy", np.__version__)
    dep_table.add_row("scikit-learn", sklearn.__version__)

    console.print(dep_table)


def main() -> None:
    """Main entry point for debug CLI."""
    try:
        cli()
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        if "--verbose" in sys.argv or "-v" in sys.argv:
            console.print_exception()
        sys.exit(1)


if __name__ == "__main__":
    main()
