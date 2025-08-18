#!/usr/bin/env python3
"""
Test script for threat classification system with diverse data
"""

import json
import os
import sys

import pandas as pd

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from dmv_scam_analysis.core.classifier import MLThreatClassifier


def load_test_data(dataset_name):
    """Load test data from JSON files"""
    file_path = f"test_data/{dataset_name}_messages.json"

    if not os.path.exists(file_path):
        print(f"❌ File not found: {file_path}")
        return None

    try:
        with open(file_path, "r") as f:
            data = json.load(f)

        # Handle different JSON structures
        if "messages" in data:
            messages = data["messages"]
        else:
            messages = data

        # Convert to DataFrame with expected columns
        df = pd.DataFrame(messages)

        # Ensure we have the required columns
        if "text" not in df.columns and "message" in df.columns:
            df["text"] = df["message"]

        # Add synthetic datetime if not present
        if "readable_date" not in df.columns and "timestamp" in df.columns:
            df["readable_date"] = pd.to_datetime(df["timestamp"])
        elif "readable_date" not in df.columns:
            # Generate synthetic timestamps
            base_time = pd.Timestamp("2024-01-01 10:00:00")
            df["readable_date"] = [
                base_time + pd.Timedelta(hours=i) for i in range(len(df))
            ]

        # Add synthetic is_from_me column if not present
        if "is_from_me" not in df.columns:
            # Assume half are sent, half received for behavioral analysis
            df["is_from_me"] = [i % 2 for i in range(len(df))]

        # Add handle_id if not present
        if "handle_id" not in df.columns:
            df["handle_id"] = [f"contact_{i % 3}" for i in range(len(df))]

        return df

    except Exception as e:
        print(f"❌ Error loading {file_path}: {e}")
        return None


def run_classification_tests():
    """Run classification tests using the MLThreatClassifier"""

    print("🔍 Starting Threat Classification System Tests")
    print("=" * 50)

    # Initialize classifier
    classifier = MLThreatClassifier()

    # Test with different datasets
    datasets = ["legitimate", "scam", "mixed"]
    results = {}

    for dataset in datasets:
        print(f"\n📊 Testing with {dataset} dataset...")

        # Load dataset
        df = load_test_data(dataset)
        if df is None:
            continue

        print(f"  📈 Loaded {len(df)} messages from {dataset} dataset")

        try:
            # Extract features and train
            print("  🔧 Extracting ML features...")
            features = classifier.extract_ml_features(df, include_labels=True)

            if not features:
                print(f"  ❌ Failed to extract features for {dataset} dataset")
                continue

            print(
                f"  ✓ Extracted {len(features['feature_names'])} features from {features['message_count']} messages"
            )

            # Train classifier
            print("  🤖 Training threat classifier...")
            training_results = classifier.train_threat_classifier(features)

            if not training_results or "error" in training_results:
                print(
                    f"  ❌ Training failed for {dataset} dataset: {training_results.get('error', 'unknown error')}"
                )
                continue

            # Make predictions
            print("  🔮 Making threat predictions...")
            predictions = classifier.predict_threat_classification(df)

            if "error" in predictions:
                print(
                    f"  ❌ Prediction failed for {dataset} dataset: {predictions['error']}"
                )
                continue

            # Store results
            results[dataset] = {
                "training_results": training_results,
                "predictions": predictions,
                "message_count": len(df),
            }

            # Display results
            print(f"\n  📋 Results for {dataset} dataset:")
            print(f"    Dataset: {dataset}")

            # Get the best model's accuracy
            best_model = training_results.get("best_model", "unknown")
            if best_model in training_results.get("training_results", {}):
                accuracy = training_results["training_results"][best_model].get(
                    "accuracy", 0
                )
                print(f"    Accuracy: {accuracy:.3f} (using {best_model})")
            else:
                print(f"    Best model: {best_model}")

            # Show prediction distribution
            pred_counts = {}
            for pred in predictions.get("predictions", []):
                pred_counts[pred] = pred_counts.get(pred, 0) + 1

            print("    Prediction distribution:")
            for pred_type, count in pred_counts.items():
                percentage = (count / len(predictions.get("predictions", [1]))) * 100
                print(f"      {pred_type}: {count} ({percentage:.1f}%)")

            # Show confidence information
            if "max_threat_probability" in predictions:
                max_prob = predictions["max_threat_probability"]
                risk_level = predictions.get("threat_risk_level", "UNKNOWN")
                print(f"    Max threat probability: {max_prob:.3f}")
                print(f"    Risk level: {risk_level}")

            print("  ✓ Classification test completed successfully")

        except Exception as e:
            print(f"  ❌ Error processing {dataset} dataset: {e}")
            import traceback

            traceback.print_exc()

    # Summary
    print("\n🎯 Test Summary")
    print("=" * 30)

    if results:
        print(f"✓ Successfully tested {len(results)} datasets:")
        for dataset, result in results.items():
            training_res = result["training_results"]
            best_model = training_res.get("best_model", "unknown")
            if best_model in training_res.get("training_results", {}):
                accuracy = training_res["training_results"][best_model].get(
                    "accuracy", 0
                )
                print(
                    f"  • {dataset}: {accuracy:.3f} accuracy ({result['message_count']} messages)"
                )
            else:
                print(f"  • {dataset}: {result['message_count']} messages processed")

        # Test ensemble functionality
        print("\n🔧 Testing ensemble functionality...")
        try:
            # Use the mixed dataset for ensemble testing
            if "mixed" in results:
                test_df = load_test_data("mixed")
                if test_df is not None:
                    # Extract a few text samples
                    test_texts = test_df["text"].head(5).tolist()

                    # Test ensemble training
                    feature_data = classifier.extract_ml_features(
                        test_df, include_labels=True
                    )
                    ensemble_results = classifier.train_ensemble(feature_data)

                    if "error" not in ensemble_results:
                        print(
                            f"  ✓ Ensemble training successful with {ensemble_results.get('ensemble_size', 0)} models"
                        )

                        # Test ensemble prediction
                        ensemble_predictions = classifier.predict_ensemble(test_texts)
                        if "error" not in ensemble_predictions:
                            print(
                                f"  ✓ Ensemble prediction successful for {len(test_texts)} samples"
                            )
                        else:
                            print(
                                f"  ❌ Ensemble prediction failed: {ensemble_predictions['error']}"
                            )
                    else:
                        print(
                            f"  ❌ Ensemble training failed: {ensemble_results['error']}"
                        )
        except Exception as e:
            print(f"  ❌ Ensemble testing failed: {e}")

        # Test anomaly detection
        print("\n🔍 Testing anomaly detection...")
        try:
            if "scam" in results:
                scam_df = load_test_data("scam")
                if scam_df is not None:
                    anomaly_results = classifier.detect_anomalies(
                        scam_df.head(10)
                    )  # Test with first 10 messages
                    if "error" not in anomaly_results:
                        isolation_forest = anomaly_results.get("isolation_forest", {})
                        overall = anomaly_results.get("overall_assessment", {})
                        print("  ✓ Anomaly detection completed")
                        print(
                            f"    Anomaly detected: {isolation_forest.get('is_anomaly', False)}"
                        )
                        print(
                            f"    Anomaly likelihood: {overall.get('anomaly_likelihood', 0)}%"
                        )
                    else:
                        print(
                            f"  ❌ Anomaly detection failed: {anomaly_results['error']}"
                        )
        except Exception as e:
            print(f"  ❌ Anomaly detection testing failed: {e}")

    else:
        print("❌ No datasets were successfully processed")

    print("\n🏁 Threat classification testing completed!")
    return results


if __name__ == "__main__":
    results = run_classification_tests()
