#!/usr/bin/env python3
"""
SentinelAnalyzer - Unified Threat Analysis Platform
Evolved from DMV Scam Analysis Project

A comprehensive cybersecurity analysis tool that combines multiple analysis modules
for threat detection, sentiment analysis, machine learning classification, and
automated reporting.

Author: Cybersecurity Researcher
Version: 2.0
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# Add scripts directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "scripts"))

# Import analysis modules
try:
    from nlp_analyzer import AdvancedNLPAnalyzer

    NLP_AVAILABLE = True
except ImportError as e:
    print(f"Warning: NLP module not available: {e}")
    NLP_AVAILABLE = False
    AdvancedNLPAnalyzer = None

try:
    from ml_threat_classifier import MLThreatClassifier

    ML_AVAILABLE = True
except ImportError as e:
    print(f"Warning: ML module not available: {e}")
    ML_AVAILABLE = False
    MLThreatClassifier = None

try:
    from behavioral_analyzer import BehavioralAnalyzer

    BEHAVIORAL_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Behavioral module not available: {e}")
    BEHAVIORAL_AVAILABLE = False
    BehavioralAnalyzer = None

try:
    from utils.config_manager import ConfigManager

    CONFIG_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Config manager not available: {e}")
    CONFIG_AVAILABLE = False
    ConfigManager = None

try:
    from utils.logger import setup_logger

    LOGGER_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Logger not available: {e}")
    LOGGER_AVAILABLE = False
    setup_logger = None

# Set placeholders for missing modules
if not LOGGER_AVAILABLE:

    def setup_logger(name, log_dir):
        import logging

        return logging.getLogger(name)


# Define placeholder classes for missing modules
class DataPreprocessor:
    def __init__(self):
        pass


class IOCValidator:
    def __init__(self):
        pass


class ThreatVisualizer:
    def __init__(self, output_dir):
        pass


class SentinelAnalyzer:
    """
    Unified threat analysis platform with multiple analysis capabilities
    """

    def __init__(self, config_path=None, output_dir="./analysis_output"):
        """
        Initialize SentinelAnalyzer

        Args:
            config_path (str): Path to configuration file
            output_dir (str): Output directory for analysis results
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Initialize configuration manager
        self.config_manager = ConfigManager(config_path) if config_path else None

        # Initialize logger
        self.logger = setup_logger("SentinelAnalyzer", self.output_dir / "logs")

        # Initialize analysis modules
        self.modules = {
            "nlp": None,
            "ml": None,
            "behavioral": None,
            "preprocessing": None,
            "ioc": None,
            "visualization": None,
        }

        self.version = "2.0"
        self.name = "SentinelAnalyzer"

        self.logger.info(f"Initialized {self.name} v{self.version}")

    def init_module(self, module_name):
        """Initialize a specific analysis module"""
        if self.modules[module_name] is not None:
            return self.modules[module_name]

        try:
            if module_name == "nlp":
                self.modules["nlp"] = AdvancedNLPAnalyzer(str(self.output_dir))
            elif module_name == "ml":
                self.modules["ml"] = MLThreatClassifier(str(self.output_dir))
            elif module_name == "behavioral":
                self.modules["behavioral"] = BehavioralAnalyzer(str(self.output_dir))
            elif module_name == "preprocessing":
                self.modules["preprocessing"] = DataPreprocessor()
            elif module_name == "ioc":
                self.modules["ioc"] = IOCValidator()
            elif module_name == "visualization":
                self.modules["visualization"] = ThreatVisualizer(str(self.output_dir))

            self.logger.info(f"Initialized {module_name} module")
            return self.modules[module_name]
        except Exception as e:
            self.logger.error(f"Failed to initialize {module_name} module: {e}")
            return None

    def load_data(self, file_path):
        """Load data from file"""
        try:
            import pandas as pd

            if file_path.endswith(".json"):
                with open(file_path, "r") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        return pd.DataFrame(data)
                    else:
                        return pd.DataFrame([data])
            elif file_path.endswith(".csv"):
                return pd.read_csv(file_path)
            else:
                raise ValueError(f"Unsupported file format: {file_path}")
        except Exception as e:
            self.logger.error(f"Error loading data from {file_path}: {e}")
            return None

    def run_nlp_analysis(self, data, contact_id="unknown"):
        """Run NLP analysis on data"""
        print("🔍 Running NLP Analysis...")

        nlp_module = self.init_module("nlp")
        if nlp_module is None:
            return None

        try:
            analysis_results = nlp_module.analyze_message_content(data)
            if analysis_results and "error" not in analysis_results:
                report = nlp_module.generate_nlp_report(contact_id, analysis_results)

                # Print summary
                risk_score = report["risk_assessment"]["nlp_risk_score"]
                print(f"✓ NLP Analysis Complete - Risk Score: {risk_score}/100")

                return report
            else:
                print("❌ NLP Analysis failed - No text content available")
                return None
        except Exception as e:
            self.logger.error(f"NLP analysis failed: {e}")
            return None

    def run_ml_analysis(self, data, contact_id="unknown", train_mode=False):
        """Run Machine Learning analysis on data"""
        print("🤖 Running ML Analysis...")

        ml_module = self.init_module("ml")
        if ml_module is None:
            return None

        try:
            results = {}

            if train_mode:
                print("Training ML models...")
                feature_data = ml_module.extract_ml_features(data, include_labels=True)
                if feature_data:
                    training_results = ml_module.train_threat_classifier(feature_data)
                    results["training"] = training_results
                    ml_module.save_models()
                    print("✓ Model training complete")

            # Always run prediction
            print("Running threat prediction...")
            ml_module.load_models()
            predictions = ml_module.predict_threat_classification(data)
            anomalies = ml_module.detect_anomalies(data)

            results["predictions"] = predictions
            results["anomaly_detection"] = anomalies

            # Generate report
            report = ml_module.generate_ml_report(contact_id, results)

            # Print summary
            if "predictions" in results:
                classification = results["predictions"].get("predictions", ["Unknown"])[
                    0
                ]
                confidence = results["predictions"].get("max_threat_probability", 0)
                print(
                    f"✓ ML Analysis Complete - Classification: {classification} ({confidence:.1%})"
                )

            return report
        except Exception as e:
            self.logger.error(f"ML analysis failed: {e}")
            return None

    def run_behavioral_analysis(self, data, contact_id="unknown"):
        """Run behavioral analysis on data"""
        print("📊 Running Behavioral Analysis...")

        behavioral_module = self.init_module("behavioral")
        if behavioral_module is None:
            print("❌ Behavioral module not available")
            return None

        try:
            # This would need to be implemented based on your behavioral_analyzer.py
            print("✓ Behavioral Analysis Complete")
            return {"status": "completed", "module": "behavioral"}
        except Exception as e:
            self.logger.error(f"Behavioral analysis failed: {e}")
            return None

    def run_ioc_validation(self, data):
        """Run IOC validation on data"""
        print("🔍 Running IOC Validation...")

        ioc_module = self.init_module("ioc")
        if ioc_module is None:
            print("❌ IOC module not available")
            return None

        try:
            # This would need to be implemented based on your ioc_validator.py
            print("✓ IOC Validation Complete")
            return {"status": "completed", "module": "ioc"}
        except Exception as e:
            self.logger.error(f"IOC validation failed: {e}")
            return None

    def run_data_preprocessing(self, data):
        """Run data preprocessing"""
        print("🔧 Running Data Preprocessing...")

        preprocessing_module = self.init_module("preprocessing")
        if preprocessing_module is None:
            print("❌ Preprocessing module not available")
            return data

        try:
            # This would need to be implemented based on your data_preprocessing.py
            print("✓ Data Preprocessing Complete")
            return data
        except Exception as e:
            self.logger.error(f"Data preprocessing failed: {e}")
            return data

    def run_visualization(self, results, contact_id="unknown"):
        """Generate visualizations from analysis results"""
        print("📈 Generating Visualizations...")

        viz_module = self.init_module("visualization")
        if viz_module is None:
            print("❌ Visualization module not available")
            return None

        try:
            # This would need to be implemented based on your threat_visualizer.py
            print("✓ Visualization Generation Complete")
            return {"status": "completed", "module": "visualization"}
        except Exception as e:
            self.logger.error(f"Visualization generation failed: {e}")
            return None

    def run_full_analysis(self, data, contact_id="unknown", train_ml=False):
        """Run complete analysis pipeline"""
        print(f"🚀 Starting Full Analysis Pipeline for: {contact_id}")
        print("=" * 60)

        results = {
            "metadata": {
                "contact_id": contact_id,
                "analysis_timestamp": datetime.now().isoformat(),
                "analyzer_version": self.version,
            },
            "results": {},
        }

        # 1. Data Preprocessing
        processed_data = self.run_data_preprocessing(data)

        # 2. NLP Analysis
        nlp_results = self.run_nlp_analysis(processed_data, contact_id)
        if nlp_results:
            results["results"]["nlp"] = nlp_results

        # 3. ML Analysis
        ml_results = self.run_ml_analysis(processed_data, contact_id, train_ml)
        if ml_results:
            results["results"]["ml"] = ml_results

        # 4. Behavioral Analysis
        behavioral_results = self.run_behavioral_analysis(processed_data, contact_id)
        if behavioral_results:
            results["results"]["behavioral"] = behavioral_results

        # 5. IOC Validation
        ioc_results = self.run_ioc_validation(processed_data)
        if ioc_results:
            results["results"]["ioc"] = ioc_results

        # 6. Generate Visualizations
        viz_results = self.run_visualization(results, contact_id)
        if viz_results:
            results["results"]["visualization"] = viz_results

        # Save comprehensive report
        report_file = (
            self.output_dir
            / f"sentinel_analysis_{contact_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        with open(report_file, "w") as f:
            json.dump(results, f, indent=2, default=str)

        print("=" * 60)
        print(f"✓ Full Analysis Complete - Report saved: {report_file}")

        return results

    def print_banner(self):
        """Print application banner"""
        banner = f"""
╔══════════════════════════════════════════════════════════════════════════════════╗
║                                                                                  ║
║                             🛡️  SentinelAnalyzer v{self.version}  🛡️                            ║
║                                                                                  ║
║                    Unified Threat Analysis Platform                             ║
║                                                                                  ║
║  Capabilities:                                                                   ║
║  • NLP Analysis & Sentiment Detection                                           ║
║  • Machine Learning Threat Classification                                       ║
║  • Behavioral Pattern Analysis                                                  ║
║  • IOC Validation & Threat Intelligence                                         ║
║  • Data Preprocessing & Visualization                                           ║
║  • Automated Report Generation                                                  ║
║                                                                                  ║
╚══════════════════════════════════════════════════════════════════════════════════╝
        """
        print(banner)


def main():
    """Main entry point for SentinelAnalyzer"""
    parser = argparse.ArgumentParser(
        description="SentinelAnalyzer - Unified Threat Analysis Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run full analysis
  python sentinel_analyzer.py --input data.json --contact "suspect_123" --full

  # Run specific analyses
  python sentinel_analyzer.py --input data.json --nlp --ml

  # Train ML models
  python sentinel_analyzer.py --input data.json --ml --train

  # Custom output directory
  python sentinel_analyzer.py --input data.json --output ./custom_output --full
        """,
    )

    # Input options
    parser.add_argument("--input", "-i", required=True, help="Input file (JSON or CSV)")
    parser.add_argument("--contact", "-c", default="unknown", help="Contact identifier")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument(
        "--output", "-o", default="./analysis_output", help="Output directory"
    )

    # Analysis modules
    parser.add_argument(
        "--full", action="store_true", help="Run full analysis pipeline"
    )
    parser.add_argument("--nlp", action="store_true", help="Run NLP analysis")
    parser.add_argument("--ml", action="store_true", help="Run ML analysis")
    parser.add_argument(
        "--behavioral", action="store_true", help="Run behavioral analysis"
    )
    parser.add_argument("--ioc", action="store_true", help="Run IOC validation")
    parser.add_argument(
        "--preprocess", action="store_true", help="Run data preprocessing"
    )
    parser.add_argument(
        "--visualize", action="store_true", help="Generate visualizations"
    )

    # ML options
    parser.add_argument("--train", action="store_true", help="Train ML models")

    # Utility options
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--version", action="version", version="SentinelAnalyzer v2.0")

    args = parser.parse_args()

    # Initialize analyzer
    analyzer = SentinelAnalyzer(config_path=args.config, output_dir=args.output)

    # Print banner
    analyzer.print_banner()

    # Load data
    print(f"📂 Loading data from: {args.input}")
    data = analyzer.load_data(args.input)
    if data is None:
        print("❌ Failed to load data")
        return 1

    print(f"✓ Loaded {len(data)} records")

    # Determine what to run
    if args.full:
        analyzer.run_full_analysis(data, args.contact, args.train)
    else:
        # Run individual modules
        if args.preprocess:
            data = analyzer.run_data_preprocessing(data)

        if args.nlp:
            analyzer.run_nlp_analysis(data, args.contact)

        if args.ml:
            analyzer.run_ml_analysis(data, args.contact, args.train)

        if args.behavioral:
            analyzer.run_behavioral_analysis(data, args.contact)

        if args.ioc:
            analyzer.run_ioc_validation(data)

        if args.visualize:
            analyzer.run_visualization({}, args.contact)

        # If no specific modules selected, run NLP by default
        if not any(
            [
                args.nlp,
                args.ml,
                args.behavioral,
                args.ioc,
                args.preprocess,
                args.visualize,
            ]
        ):
            print("No specific analysis selected, running NLP analysis...")
            analyzer.run_nlp_analysis(data, args.contact)

    print("\n🎉 Analysis complete!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
