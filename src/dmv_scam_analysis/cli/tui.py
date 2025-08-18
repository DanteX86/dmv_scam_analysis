"""Terminal User Interface (TUI) for DMV Scam Analysis.

Provides an interactive terminal experience to:
- Analyze a file (JSON/CSV) with Behavioral and NLP modules
- Analyze a single message
- View recent reports and open dashboard HTML
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import click
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

from ..analysis.behavioral import BehavioralAnalyzer
from ..analysis.sentiment import AdvancedNLPAnalyzer
from ..core.extractor import iMessageAnalyzer
from ..core.classifier import MLThreatClassifier as ThreatClassifier


console = Console()


def _safe_mkdir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _load_messages_from_file(file_path: Path) -> List[Dict[str, Any]]:
    if file_path.suffix.lower() == ".json":
        with file_path.open("r") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            raise ValueError("JSON must be a list of message dicts")
    if file_path.suffix.lower() == ".csv":
        import pandas as pd

        df = pd.read_csv(file_path)
        return df.to_dict("records")  # type: ignore[no-any-return]
    raise ValueError("Unsupported file format. Use .json or .csv")


def _render_header() -> None:
    console.print(
        Panel(
            "🛡️ DMV Scam Analysis — Terminal UI",
            style="bold cyan",
            border_style="cyan",
        )
    )


def _list_dashboard_templates() -> list[str]:
    """Discover available Jinja dashboard templates.

    Returns a list of template base names (without .html.j2),
    e.g. ["threat_dashboard", "executive"].
    """
    # templates path: dmv_scam_analysis/dashboard/templates
    try:
        pkg_root = Path(__file__).resolve().parents[1]  # dmv_scam_analysis/
        templates_dir = pkg_root / "dashboard" / "templates"
        if not templates_dir.exists():
            return ["threat_dashboard"]
        names = []
        for p in templates_dir.glob("*.html.j2"):
            (
                names.append(p.stem.replace(".html", ""))
                if p.stem.endswith(".html")
                else names.append(p.stem)
            )
        # Normalize unique and sorted
        bases = sorted(set(n if not n.endswith(".html") else n[:-5] for n in names))
        return bases or ["threat_dashboard"]
    except Exception:
        return ["threat_dashboard"]


def _show_main_menu() -> int:
    table = Table(
        title="Main Menu",
        show_header=False,
        box=box.SIMPLE,
        padding=(0, 1),
    )
    table.add_column("#", justify="right", width=3)
    table.add_column("Action", no_wrap=True)
    table.add_row("1", "Analyze file (JSON/CSV)")
    table.add_row("2", "Analyze single message")
    table.add_row("3", "View recent reports")
    table.add_row("4", "Open dashboard HTML (path)")
    table.add_row("5", "Analyze iMessage DB (by contact)")
    table.add_row("6", "Generate Dashboard (HTML)")
    table.add_row("0", "Quit")
    console.print(table)
    choice = IntPrompt.ask("Choose an option", choices=["0", "1", "2", "3", "4", "5", "6"])
    return int(choice)


def _summarize_behavioral(report: Dict[str, Any]) -> Tuple[int, str]:
    risk = report.get("risk_assessment", {})
    score = int(risk.get("behavioral_risk_score", 0))
    level = str(risk.get("risk_level", "UNKNOWN"))
    return score, level


def _print_behavioral_summary(report: Dict[str, Any]) -> None:
    score, level = _summarize_behavioral(report)
    factors = report.get("risk_assessment", {}).get("risk_factors", [])
    lines = [
        f"Risk Score: {score}/100",
        f"Risk Level: {level}",
    ]
    if factors:
        lines.append("")
        lines.append("Key Risk Factors:")
        for f in factors:
            lines.append(f"• {f}")
    console.print(Panel("\n".join(lines), title="Behavioral Summary", border_style="green"))


def _print_nlp_summary(nlp_report: Dict[str, Any]) -> None:
    risk = nlp_report.get("risk_assessment", {})
    score = int(risk.get("nlp_risk_score", 0))
    level = str(risk.get("risk_level", "UNKNOWN"))
    lines = [
        f"NLP Risk Score: {score}/100",
        f"Risk Level: {level}",
    ]
    console.print(Panel("\n".join(lines), title="NLP Summary", border_style="magenta"))


def _print_classifier_summary(pred_result: Any) -> None:
    """Print a concise classifier summary panel.

    Supports either:
    - list/array of labels (first item is the prediction), or
    - dict with keys like 'predictions', 'max_threat_probability', 'probabilities'.
    """
    title = "ML Classification"
    try:
        label = "Unknown"
        confidence = None
        details = None

        if isinstance(pred_result, dict):
            # Try common shapes
            if isinstance(pred_result.get("predictions"), list) and pred_result["predictions"]:
                label = str(pred_result["predictions"][0])
            elif isinstance(pred_result.get("label"), str):
                label = pred_result.get("label", "Unknown")

            # Confidence extraction
            if isinstance(pred_result.get("max_threat_probability"), (int, float)):
                confidence = float(pred_result["max_threat_probability"])  # 0..1
            elif isinstance(pred_result.get("confidence"), (int, float)):
                confidence = float(pred_result["confidence"])  # 0..1 or 0..100

            # Optional probabilities map
            probs = pred_result.get("probabilities")
            if isinstance(probs, dict):
                # Show top-3
                top3 = sorted(probs.items(), key=lambda kv: kv[1], reverse=True)[:3]
                details = [f"{k}: {v:.2f}" for k, v in top3]

        elif isinstance(pred_result, (list, tuple)) and pred_result:
            label = str(pred_result[0])
        else:
            label = str(pred_result)

        lines = [f"Prediction: {label}"]
        if confidence is not None:
            # Normalize if > 1
            conf_pct = confidence * 100.0 if confidence <= 1 else confidence
            lines.append(f"Confidence: {conf_pct:.1f}%")
        if details:
            lines.append("")
            lines.append("Top classes:")
            lines.extend([f"• {d}" for d in details])

        console.print(Panel("\n".join(lines), title=title, border_style="blue"))
    except Exception as e:  # noqa: BLE001
        console.print(
            Panel(f"Failed to render classification: {e}", title=title, border_style="red")
        )


def _list_recent_reports(output_dir: Path, limit: int = 10) -> List[Path]:
    if not output_dir.exists():
        return []
    files = list(output_dir.glob("*.json")) + list(output_dir.glob("*.txt"))
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return files[:limit]


def _show_reports_table(files: List[Path]) -> None:
    if not files:
        console.print("No reports found.", style="yellow")
        return
    table = Table(title="Recent Reports", box=box.SIMPLE)
    table.add_column("#", justify="right", width=3)
    table.add_column("File")
    table.add_column("Modified")
    for idx, f in enumerate(files, start=1):
        mtime = datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        table.add_row(str(idx), str(f), mtime)
    console.print(table)


def _generate_csv_filename(contact: str) -> str:
    """Generate CSV filename with sanitized contact and timestamp."""
    import re
    from datetime import datetime

    # Sanitize contact identifier
    sanitized = re.sub(r"[^\w\-@+]", "_", contact)
    sanitized = sanitized.strip("_")[:50]  # Limit length

    # Generate timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    return f"messages_{sanitized}_{timestamp}.csv"


def run_tui(output_dir: Optional[str] = None, dashboard_path: Optional[str] = None) -> int:
    """Run interactive TUI.

    Args:
        output_dir: Directory where analysis outputs are written.
        dashboard_path: Path to dashboard HTML to open.
    Returns:
        Exit code (0 = success).
    """
    try:
        out_dir = Path(output_dir or "./analysis_output").expanduser()
        _safe_mkdir(out_dir)

        analyzer = BehavioralAnalyzer(output_dir=str(out_dir))
        nlp = AdvancedNLPAnalyzer(output_dir=str(out_dir))
        classifier = ThreatClassifier()

        while True:
            console.clear()
            _render_header()
            choice = _show_main_menu()

            if choice == 0:
                console.print("Goodbye!", style="cyan")
                return 0

            if choice == 1:
                # Analyze file
                file_in = Prompt.ask(
                    "Enter path to messages file (.json or .csv)", default="messages.json"
                )
                file_path = Path(file_in).expanduser()
                try:
                    messages = _load_messages_from_file(file_path)
                except Exception as e:  # noqa: BLE001
                    console.print(f"[red]Failed to read file[/red]: {e}")
                    click.pause()
                    continue

                # Behavioral
                import pandas as pd

                df = pd.DataFrame(messages)
                temporal = analyzer.analyze_temporal_patterns(df)
                automation = analyzer.detect_automation_indicators(df)
                behavioral_report = analyzer.generate_behavioral_report(
                    file_path.stem, temporal, automation
                )
                _print_behavioral_summary(behavioral_report)

                # NLP
                nlp_analysis = nlp.analyze_message_content(df)
                if nlp_analysis:
                    nlp_report = nlp.generate_nlp_report(file_path.stem, nlp_analysis)
                    _print_nlp_summary(nlp_report)

                # ML Classification
                try:
                    pred = classifier.predict(df)
                    _print_classifier_summary(pred)
                except Exception as e:  # noqa: BLE001
                    console.print(f"[yellow]Classifier unavailable[/yellow]: {e}")

                console.print(
                    Panel(f"Reports saved to: {out_dir}", border_style="cyan", title="Saved")
                )
                click.pause()

            elif choice == 2:
                # Analyze single message
                text = Prompt.ask("Enter message text")
                source = Prompt.ask("Enter source", default="cli")

                message = {
                    "text": text,
                    "source": source,
                    "timestamp": datetime.now().isoformat(),
                    "is_from_me": 0,
                    "readable_date": datetime.now().isoformat(),
                }

                import pandas as pd

                df = pd.DataFrame([message])
                temporal = analyzer.analyze_temporal_patterns(df)
                automation = analyzer.detect_automation_indicators(df)
                behavioral_report = analyzer.generate_behavioral_report(
                    "single_message", temporal, automation
                )
                _print_behavioral_summary(behavioral_report)

                nlp_analysis = nlp.analyze_message_content(df)
                if nlp_analysis:
                    nlp_report = nlp.generate_nlp_report("single_message", nlp_analysis)
                    _print_nlp_summary(nlp_report)

                # ML Classification
                try:
                    pred = classifier.predict(df)
                    _print_classifier_summary(pred)
                except Exception as e:  # noqa: BLE001
                    console.print(f"[yellow]Classifier unavailable[/yellow]: {e}")

                click.pause()

            elif choice == 3:
                # View recent reports
                files = _list_recent_reports(out_dir, limit=15)
                _show_reports_table(files)
                if files:
                    if Confirm.ask("Open a file?", default=False):
                        idx = IntPrompt.ask(
                            "Enter # to open", choices=[str(i) for i in range(1, len(files) + 1)]
                        )
                        target = files[int(idx) - 1]
                        try:
                            import webbrowser

                            webbrowser.open(target.as_uri())
                            console.print(f"Opened: {target}")
                        except Exception as e:  # noqa: BLE001
                            console.print(f"[red]Failed to open[/red]: {e}")
                click.pause()

            elif choice == 4:
                # Open dashboard HTML (path)
                path_in = dashboard_path or Prompt.ask(
                    "Enter path to dashboard HTML", default="dashboard.html"
                )
                path_obj = Path(str(path_in)).expanduser()
                if not path_obj.exists():
                    console.print(f"[yellow]Not found[/yellow]: {path_obj}")
                    click.pause()
                    continue
                try:
                    import webbrowser

                    webbrowser.open(path_obj.as_uri())
                    console.print(f"Opened: {path_obj}")
                except Exception as e:  # noqa: BLE001
                    console.print(f"[red]Failed to open[/red]: {e}")
                click.pause()

            elif choice == 5:
                # Analyze iMessage DB by contact
                db_path = Prompt.ask(
                    "Path to iMessage chat.db",
                    default=str(Path("~/Library/Messages/chat.db").expanduser()),
                )
                contact = Prompt.ask("Contact identifier (phone/email)", default="+1")
                limit_str = Prompt.ask("Limit messages (optional)", default="").strip()
                limit_val = int(limit_str) if limit_str.isdigit() else None

                im = iMessageAnalyzer(db_path=db_path, output_dir=str(out_dir))
                try:
                    if not im.connect_database():
                        click.pause()
                        continue
                    df = im.extract_messages_by_contact(contact, limit_val)
                    if df is None or df.empty:
                        console.print(f"[yellow]No messages found for {contact}[/yellow]")
                        click.pause()
                        continue

                    # Export extracted messages to CSV
                    csv_filename = _generate_csv_filename(contact)
                    csv_path = out_dir / csv_filename
                    export_success = im.export_messages_csv(df, str(csv_path))

                    if export_success:
                        console.print(
                            Panel(
                                f"Messages exported to: {csv_path}",
                                border_style="green",
                                title="CSV Export",
                            )
                        )

                    # Behavioral
                    temporal = analyzer.analyze_temporal_patterns(df)
                    automation = analyzer.detect_automation_indicators(df)
                    behavioral_report = analyzer.generate_behavioral_report(
                        contact, temporal, automation
                    )
                    _print_behavioral_summary(behavioral_report)

                    # NLP
                    nlp_analysis = nlp.analyze_message_content(df)
                    if nlp_analysis:
                        nlp_report = nlp.generate_nlp_report(contact, nlp_analysis)
                        _print_nlp_summary(nlp_report)

                    # ML Classification
                    try:
                        pred = classifier.predict(df)
                        _print_classifier_summary(pred)
                    except Exception as e:  # noqa: BLE001
                        console.print(f"[yellow]Classifier unavailable[/yellow]: {e}")

                    console.print(
                        Panel(
                            f"Reports saved to: {out_dir}",
                            border_style="cyan",
                            title="Saved",
                        )
                    )
                except Exception as e:  # noqa: BLE001
                    console.print(f"[red]DB analysis failed[/red]: {e}")
                finally:
                    try:
                        im.close_connection()
                    except Exception:
                        pass
                click.pause()

            elif choice == 6:
                # Generate Dashboard (HTML)
                from ..dashboard.threat_dashboard import ThreatDashboard

                out_name = Prompt.ask("Output HTML file name", default="threat_dashboard.html")
                data_dir = Prompt.ask("Dashboard data directory", default="dashboard_data")
                # Discover templates and present a menu
                templates = _list_dashboard_templates()
                table = Table(title="Available Templates", show_header=True, header_style="bold")
                table.add_column("#", justify="right", width=3)
                table.add_column("Template")
                for idx, t in enumerate(templates, start=1):
                    table.add_row(str(idx), t)
                console.print(table)
                choice = IntPrompt.ask(
                    "Choose template #",
                    choices=[str(i) for i in range(1, len(templates) + 1)],
                    default=1,
                )
                template_base = templates[int(choice) - 1]
                try:
                    dash = ThreatDashboard(data_dir=data_dir)
                    path = dash.generate_dashboard_html(
                        output_file=out_name, template=template_base
                    )
                    console.print(Panel(f"Dashboard generated: {path}", border_style="green"))

                    # Offer to open
                    if Confirm.ask("Open in browser?", default=False):
                        import webbrowser

                        webbrowser.open(Path(path).resolve().as_uri())
                except Exception as e:  # noqa: BLE001
                    console.print(f"[red]Dashboard generation failed[/red]: {e}")
                finally:
                    click.pause()

    except KeyboardInterrupt:
        console.print("\nInterrupted.", style="yellow")
        return 130
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]Fatal error[/red]: {e}")
        return 1

    return 0
