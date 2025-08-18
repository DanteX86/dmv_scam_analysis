#!/usr/bin/env python3
"""
Test the threat classification system with diverse data
Exact implementation as requested in the task
"""

import json
import os
import sys

import pandas as pd

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from dmv_scam_analysis.core.classifier import MLThreatClassifier


def main():
    """Run classification tests using the MLThreatClassifier as requested"""

    # Initialize classifier
    classifier = MLThreatClassifier()

    # Test with different datasets
    for dataset in ["legitimate", "scam", "mixed"]:
        print(f"\n{'='*50}")
        print(f"Testing with {dataset} dataset")
        print(f"{'='*50}")

        # Load the dataset
        try:
            with open(f"test_data/{dataset}_messages.json", "r") as f:
                data = json.load(f)

            # Handle different JSON structures
            if "messages" in data:
                messages = data["messages"]
            else:
                messages = data

            # Convert to DataFrame
            df = pd.DataFrame(messages)

            # Ensure we have required columns for feature extraction
            if "readable_date" not in df.columns and "timestamp" in df.columns:
                df["readable_date"] = pd.to_datetime(df["timestamp"])
            elif "readable_date" not in df.columns:
                # Generate synthetic timestamps for demonstration
                base_time = pd.Timestamp("2024-01-01 10:00:00")
                df["readable_date"] = [
                    base_time + pd.Timedelta(hours=i) for i in range(len(df))
                ]

            # Add behavioral columns if missing
            if "is_from_me" not in df.columns:
                df["is_from_me"] = [i % 2 for i in range(len(df))]

            if "handle_id" not in df.columns:
                df["handle_id"] = [f"contact_{i % 3}" for i in range(len(df))]

            print(f"Loaded {len(df)} messages from {dataset} dataset")

            # Extract features and train
            print("Extracting ML features...")
            features = classifier.extract_ml_features(df, include_labels=True)

            if not features:
                print(f"Failed to extract features for {dataset} dataset")
                continue

            print(f"Extracted {len(features['feature_names'])} features")

            # Train the classifier
            print("Training threat classifier...")
            training_results = classifier.train_threat_classifier(features)

            if "error" in training_results:
                print(f"Training failed: {training_results['error']}")
                continue

            # Make predictions
            print("Making predictions...")
            predictions = classifier.predict_threat_classification(df)

            if "error" in predictions:
                print(f"Prediction failed: {predictions['error']}")
                continue

            # Evaluate accuracy - get the best model's performance
            best_model = training_results.get("best_model", "unknown")
            if best_model in training_results.get("training_results", {}):
                accuracy = training_results["training_results"][best_model].get(
                    "accuracy", 0
                )
            else:
                accuracy = 0

            # Display results as requested
            print(f"Dataset: {dataset}")
            print(
                f"Accuracy: {training_results['training_results']['random_forest']['accuracy']:.3f}"
            )

            # Additional detailed results
            print("\nDetailed Results:")
            print(f"  Messages processed: {len(df)}")
            print(f"  Best model: {best_model}")
            print(f"  Feature count: {len(features['feature_names'])}")

            # Show model performance for all trained models
            print("\nModel Performance:")
            for model_name, results in training_results["training_results"].items():
                if "error" not in results:
                    print(f"  {model_name}:")
                    print(f"    Accuracy: {results.get('accuracy', 0):.3f}")
                    print(f"    Precision: {results.get('precision', 0):.3f}")
                    print(f"    Recall: {results.get('recall', 0):.3f}")
                    print(f"    F1-Score: {results.get('f1_score', 0):.3f}")

            # Show prediction distribution
            pred_counts = {}
            for pred in predictions.get("predictions", []):
                pred_counts[pred] = pred_counts.get(pred, 0) + 1

            print("\nPrediction Distribution:")
            for pred_type, count in pred_counts.items():
                percentage = (count / len(predictions.get("predictions", [1]))) * 100
                print(f"  {pred_type}: {count} ({percentage:.1f}%)")

            # Show confidence metrics
            if "max_threat_probability" in predictions:
                print("\nThreat Assessment:")
                print(
                    f"  Max threat probability: {predictions['max_threat_probability']:.3f}"
                )
                print(
                    f"  Risk level: {predictions.get('threat_risk_level', 'UNKNOWN')}"
                )

            # Test anomaly detection on this dataset
            print("\nAnomaly Detection:")
            anomaly_results = classifier.detect_anomalies(
                df.head(10)
            )  # Test with subset
            if "error" not in anomaly_results:
                isolation_forest = anomaly_results.get("isolation_forest", {})
                overall = anomaly_results.get("overall_assessment", {})
                print(
                    f"  Anomaly detected: {isolation_forest.get('is_anomaly', False)}"
                )
                print(f"  Anomaly likelihood: {overall.get('anomaly_likelihood', 0)}%")

                # Show primary concerns if any
                concerns = overall.get("primary_concerns", [])
                if concerns:
                    print("  Primary concerns:")
                    for concern in concerns[:3]:  # Show top 3
                        print(f"    - {concern}")
            else:
                print(f"  Anomaly detection failed: {anomaly_results['error']}")

        except FileNotFoundError:
            print(f"❌ Dataset file not found: test_data/{dataset}_messages.json")
        except Exception as e:
            print(f"❌ Error processing {dataset} dataset: {e}")
            import traceback

            traceback.print_exc()

    print(f"\n{'='*50}")
    print("Classification testing completed!")
    print(f"{'='*50}")


if __name__ == "__main__":
    main()
