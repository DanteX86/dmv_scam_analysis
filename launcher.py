#!/usr/bin/env python3
"""
SentinelAnalyzer Launcher Script
===============================

Main entry point for the DMV Scam Analysis toolkit.
Handles environment setup, configuration management, and execution modes.

Usage:
    python launcher.py [OPTIONS] [COMMAND]

Commands:
    analyze     - Run scam analysis on input data
    train       - Train machine learning models
    serve       - Start API server
    dashboard   - Launch interactive dashboard
    test        - Run test suite
    setup       - Setup project environment
    config      - Configuration management
    doctor      - System health check

Examples:
    python launcher.py analyze --input data/raw/messages.json
    python launcher.py train --model classifier
    python launcher.py serve --port 8080
    python launcher.py dashboard
    python launcher.py test --coverage
    python launcher.py setup --environment production
    python launcher.py config --show
    python launcher.py doctor
"""

import argparse
import json
import logging
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent.absolute()
sys.path.insert(0, str(PROJECT_ROOT))

# Add src to path for imports
sys.path.insert(0, str(PROJECT_ROOT / "src"))

try:
    from dmv_scam_analysis.utils.config_manager import ConfigManager
    from dmv_scam_analysis.utils.logger import setup_logging
except ImportError as e:
    print(f"❌ Error importing project modules: {e}")
    print(
        "Please ensure all dependencies are installed and the project is properly set up."
    )
    sys.exit(1)


class SentinelLauncher:
    """Main launcher class for SentinelAnalyzer."""

    def __init__(self):
        self.project_root: Path = PROJECT_ROOT
        self.config: Optional[ConfigManager] = None
        self.logger: Optional[logging.Logger] = None
        self.start_time: datetime = datetime.now()

    def setup_environment(self) -> bool:
        """Setup the project environment and dependencies."""
        try:
            # Load configuration
            self.config = ConfigManager()

            # Setup logging
            self.logger = setup_logging(
                name="SentinelLauncher",
                level=logging.DEBUG
                if self._cfg().get("environment.debug")
                else logging.INFO,
            )

            self._log().info("🚀 SentinelAnalyzer Launcher Starting...")
            self._log().info(f"📁 Project Root: {self.project_root}")
            self._log().info(f"🔧 Environment: {self._cfg().get('environment.name')}")

            # Verify critical paths
            self._verify_paths()

            # Check dependencies
            self._check_dependencies()

            return True

        except Exception as e:
            print(f"❌ Environment setup failed: {e}")
            return False

    def _verify_paths(self) -> None:
        """Verify that critical project paths exist."""
        critical_paths: List[Optional[str]] = [
            self._cfg().get("storage.files.raw_data"),
            self._cfg().get("storage.files.processed_data"),
            self._cfg().get("storage.files.interim_data"),
            self._cfg().get("paths.logs"),
            self._cfg().get("paths.models"),
        ]

        for path_str in critical_paths:
            if path_str:
                path = Path(path_str)
                if not path.exists():
                    self._log().info(f"📁 Creating directory: {path}")
                    path.mkdir(parents=True, exist_ok=True)

    def _check_dependencies(self) -> None:
        """Check if required dependencies are installed."""
        required_packages = self._cfg().get("dependencies.required_packages", [])

        for package in required_packages:
            package_name = package.split(">=")[0].split("==")[0]
            try:
                __import__(package_name.replace("-", "_"))
                self._log().debug(f"✓ {package_name} is available")
            except ImportError:
                self._log().warning(f"⚠️  {package_name} is not installed")

    def analyze(self, args: argparse.Namespace) -> int:
        """Run scam analysis on input data."""
        self._log().info("🔍 Starting scam analysis...")

        try:
            # Import analysis module
            from scripts.analysis.sentiment_analyzer import (
                SentimentAnalyzer,  # type: ignore[import-not-found]
            )
            from scripts.analysis.threat_detector import (
                ThreatDetector,  # type: ignore[import-not-found]
            )

            # Initialize analyzers
            sentiment_analyzer = SentimentAnalyzer(self.config)
            threat_detector = ThreatDetector(self.config)

            # Process input
            if args.input:
                input_path = Path(args.input)
                if not input_path.exists():
                    self._log().error(f"❌ Input file not found: {input_path}")
                    return 1

                self._log().info(f"📂 Processing input: {input_path}")

                # Load and process data
                with open(input_path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                results = []
                for item in data:
                    # Analyze sentiment
                    sentiment = sentiment_analyzer.analyze(item.get("text", ""))

                    # Detect threats
                    threats = threat_detector.analyze(item.get("text", ""))

                    results.append(
                        {
                            "id": item.get("id"),
                            "text": item.get("text"),
                            "sentiment": sentiment,
                            "threats": threats,
                            "timestamp": datetime.now().isoformat(),
                        }
                    )

                # Save results
                output_path = (
                    Path(args.output)
                    if args.output
                    else Path("data/processed/analysis_results.json")
                )
                output_path.parent.mkdir(parents=True, exist_ok=True)

                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump(results, f, indent=2, ensure_ascii=False)

                self._log().info(
                    f"✅ Analysis complete. Results saved to: {output_path}"
                )
                return 0

            else:
                self._log().error("❌ No input file specified")
                return 1

        except Exception as e:
            self._log().error(f"❌ Analysis failed: {e}")
            return 1

    def train(self, args: argparse.Namespace) -> int:
        """Train machine learning models."""
        self._log().info("🎓 Starting model training...")

        try:
            # Import training modules
            from scripts.ml.model_trainer import (
                ModelTrainer,  # type: ignore[import-not-found]
            )

            trainer = ModelTrainer(self.config)

            if args.model == "classifier":
                trainer.train_classifier(data_path=args.data, output_path=args.output)
            elif args.model == "embeddings":
                trainer.train_embeddings(data_path=args.data, output_path=args.output)
            else:
                self._log().error(f"❌ Unknown model type: {args.model}")
                return 1

            self._log().info("✅ Model training complete")
            return 0

        except Exception as e:
            self._log().error(f"❌ Training failed: {e}")
            return 1

    def serve(self, args: argparse.Namespace) -> int:
        """Start the API server."""
        self._log().info("🌐 Starting API server...")

        try:
            # Import server module
            from scripts.api.server import create_app  # type: ignore[import-not-found]

            app = create_app(self.config)

            host = args.host or self._cfg().get("server.host", "localhost")
            port = args.port or self._cfg().get("server.port", 5000)

            self._log().info(f"🚀 Server starting on {host}:{port}")

            app.run(
                host=host, port=port, debug=self._cfg().get("environment.debug", False)
            )

            return 0

        except Exception as e:
            self._log().error(f"❌ Server failed to start: {e}")
            return 1

    def dashboard(self, args: argparse.Namespace) -> int:
        """Launch interactive dashboard."""
        self._log().info("📊 Starting dashboard...")

        try:
            # Import dashboard module
            from scripts.dashboard.app import (
                create_dashboard,  # type: ignore[import-not-found]
            )

            dashboard = create_dashboard(self.config)

            port = args.port or self._cfg().get("dashboard.port", 8050)

            self._log().info(f"🎯 Dashboard starting on port {port}")
            dashboard.run_server(
                port=port, debug=self._cfg().get("environment.debug", False)
            )

            return 0

        except Exception as e:
            self._log().error(f"❌ Dashboard failed to start: {e}")
            return 1

    def test(self, args: argparse.Namespace) -> int:
        """Run the test suite."""
        self._log().info("🧪 Running test suite...")

        try:
            cmd = ["python", "-m", "pytest"]

            if args.coverage:
                cmd.extend(["--cov=scripts", "--cov-report=html", "--cov-report=term"])

            if args.verbose:
                cmd.append("-v")

            if args.parallel:
                cmd.extend(["-n", "auto"])

            # Add test directory
            cmd.append("tests/")

            result = subprocess.run(cmd, cwd=self.project_root)

            if result.returncode == 0:
                self._log().info("✅ All tests passed")
            else:
                self._log().error("❌ Some tests failed")

            return result.returncode

        except Exception as e:
            self._log().error(f"❌ Test execution failed: {e}")
            return 1

    def setup(self, args: argparse.Namespace) -> int:
        """Setup project environment."""
        self._log().info("⚙️  Setting up project environment...")

        try:
            # Create virtual environment if it doesn't exist
            venv_path = self.project_root / "venv"
            if not venv_path.exists():
                self._log().info("📦 Creating virtual environment...")
                subprocess.run([sys.executable, "-m", "venv", str(venv_path)])

            # Install dependencies
            pip_path = venv_path / "bin" / "pip"
            if not pip_path.exists():
                pip_path = venv_path / "Scripts" / "pip.exe"  # Windows

            if pip_path.exists():
                self._log().info("📥 Installing dependencies...")
                subprocess.run([str(pip_path), "install", "-r", "requirements.txt"])

            # Setup configuration for specified environment
            if args.environment:
                self._log().info(f"🔧 Setting up {args.environment} environment...")
                # Environment-specific setup logic here

            self._log().info("✅ Environment setup complete")
            return 0

        except Exception as e:
            self._log().error(f"❌ Setup failed: {e}")
            return 1

    def config_cmd(self, args: argparse.Namespace) -> int:
        """Configuration management."""
        try:
            if args.show:
                print("📋 Current Configuration:")
                print("=" * 50)
                config_dict: Dict[str, Any] = self._cfg().as_dict()  # type: ignore[assignment]
                print(json.dumps(config_dict, indent=2))

            elif args.set:
                key, value = args.set.split("=", 1)
                self._cfg().set(key, value)
                self._cfg().save()
                self._log().info(f"✅ Configuration updated: {key} = {value}")

            elif args.get:
                value = self._cfg().get(args.get)
                print(f"{args.get} = {value}")

            return 0

        except Exception as e:
            self._log().error(f"❌ Configuration operation failed: {e}")
            return 1

    def doctor(self, args: argparse.Namespace) -> int:
        """System health check."""
        self._log().info("🏥 Running system health check...")

        issues = []

        try:
            # Check Python version
            python_version = sys.version_info
            required_version = (3, 9)

            if python_version < required_version:
                issues.append(f"Python version {python_version} < {required_version}")
            else:
                self._log().info(f"✅ Python version: {python_version}")

            # Check dependencies
            required_packages = self._cfg().get("dependencies.required_packages", [])
            for package in required_packages:
                package_name = package.split(">=")[0].split("==")[0]
                try:
                    __import__(package_name.replace("-", "_"))
                    self._log().info(f"✅ {package_name} is available")
                except ImportError:
                    issues.append(f"Missing package: {package_name}")

            # Check file system
            critical_paths = [
                self._cfg().get("storage.files.raw_data"),
                self._cfg().get("storage.files.processed_data"),
                self._cfg().get("paths.logs"),
                self._cfg().get("paths.models"),
            ]

            for path_str in critical_paths:
                if path_str:
                    path = Path(path_str)
                    if path.exists():
                        self._log().info(f"✅ Directory exists: {path}")
                    else:
                        issues.append(f"Missing directory: {path}")

            # Check configuration
            try:
                # Validate configuration if method is available
                validate = getattr(self._cfg(), "_validate_config", None)
                if callable(validate):
                    validate()
                self._log().info("✅ Configuration is valid")
            except Exception as e:
                issues.append(f"Configuration error: {e}")

            # Summary
            if issues:
                self._log().warning("⚠️  Issues found:")
                for issue in issues:
                    self._log().warning(f"  - {issue}")
                return 1
            else:
                self._log().info("✅ All health checks passed")
                return 0

        except Exception as e:
            self._log().error(f"❌ Health check failed: {e}")
            return 1

    def run(self, args: List[str]) -> int:
        """Main entry point."""
        parser = self._create_parser()
        parsed_args = parser.parse_args(args)

        # Setup environment
        if not self.setup_environment():
            return 1

        # Execute command
        try:
            if parsed_args.command == "analyze":
                return self.analyze(parsed_args)
            elif parsed_args.command == "train":
                return self.train(parsed_args)
            elif parsed_args.command == "serve":
                return self.serve(parsed_args)
            elif parsed_args.command == "dashboard":
                return self.dashboard(parsed_args)
            elif parsed_args.command == "test":
                return self.test(parsed_args)
            elif parsed_args.command == "setup":
                return self.setup(parsed_args)
            elif parsed_args.command == "config":
                return self.config_cmd(parsed_args)
            elif parsed_args.command == "doctor":
                return self.doctor(parsed_args)
            else:
                parser.print_help()
                return 1

        except KeyboardInterrupt:
            self._log().info("🛑 Operation interrupted by user")
            return 130
        except Exception as e:
            self._log().error(f"❌ Unexpected error: {e}")
            return 1
        finally:
            if self.logger:
                duration = datetime.now() - self.start_time
                self._log().info(f"⏱️  Total execution time: {duration}")

    def _create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser."""
        parser = argparse.ArgumentParser(
            description="SentinelAnalyzer - DMV Scam Analysis Toolkit",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=__doc__,
        )

        subparsers = parser.add_subparsers(dest="command", help="Available commands")

        # Analyze command
        analyze_parser = subparsers.add_parser("analyze", help="Run scam analysis")
        analyze_parser.add_argument(
            "--input", "-i", required=True, help="Input data file"
        )
        analyze_parser.add_argument("--output", "-o", help="Output results file")
        analyze_parser.add_argument(
            "--batch-size", type=int, help="Batch size for processing"
        )

        # Train command
        train_parser = subparsers.add_parser("train", help="Train ML models")
        train_parser.add_argument(
            "--model",
            "-m",
            required=True,
            choices=["classifier", "embeddings"],
            help="Model type",
        )
        train_parser.add_argument("--data", "-d", help="Training data path")
        train_parser.add_argument("--output", "-o", help="Model output path")
        train_parser.add_argument(
            "--epochs", type=int, help="Number of training epochs"
        )

        # Serve command
        serve_parser = subparsers.add_parser("serve", help="Start API server")
        serve_parser.add_argument("--host", help="Server host")
        serve_parser.add_argument("--port", "-p", type=int, help="Server port")
        serve_parser.add_argument("--workers", type=int, help="Number of workers")

        # Dashboard command
        dashboard_parser = subparsers.add_parser("dashboard", help="Launch dashboard")
        dashboard_parser.add_argument("--port", "-p", type=int, help="Dashboard port")
        dashboard_parser.add_argument("--host", help="Dashboard host")

        # Test command
        test_parser = subparsers.add_parser("test", help="Run test suite")
        test_parser.add_argument(
            "--coverage", action="store_true", help="Generate coverage report"
        )
        test_parser.add_argument(
            "--verbose", "-v", action="store_true", help="Verbose output"
        )
        test_parser.add_argument(
            "--parallel", action="store_true", help="Run tests in parallel"
        )

        # Setup command
        setup_parser = subparsers.add_parser("setup", help="Setup environment")
        setup_parser.add_argument(
            "--environment",
            "-e",
            choices=["development", "production"],
            help="Environment to setup",
        )
        setup_parser.add_argument(
            "--force", action="store_true", help="Force reinstall"
        )

        # Config command
        config_parser = subparsers.add_parser("config", help="Configuration management")
        config_group = config_parser.add_mutually_exclusive_group(required=True)
        config_group.add_argument(
            "--show", action="store_true", help="Show current configuration"
        )
        config_group.add_argument("--set", help="Set configuration value (key=value)")
        config_group.add_argument("--get", help="Get configuration value")

        # Doctor command
        doctor_parser = subparsers.add_parser("doctor", help="System health check")
        doctor_parser.add_argument(
            "--fix", action="store_true", help="Attempt to fix issues"
        )

        return parser

    def _cfg(self) -> ConfigManager:
        if self.config is None:
            raise RuntimeError(
                "Configuration is not initialized. Call setup_environment() first."
            )
        return self.config

    def _log(self) -> logging.Logger:
        if self.logger is None:
            raise RuntimeError(
                "Logger is not initialized. Call setup_environment() first."
            )
        return self.logger


def main():
    """Main entry point."""
    launcher = SentinelLauncher()
    exit_code = launcher.run(sys.argv[1:])
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
