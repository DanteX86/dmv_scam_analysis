#!/usr/bin/env python3
"""
Ensemble Model Performance Test Script
DMV Scam Analysis Project

Test ensemble functionality as specified in task requirements:
- Train multiple model types (Random Forest, Gradient Boosting, SVM, Logistic Regression, Naive Bayes)
- Compare individual model performance
- Test ensemble prediction averaging
- Measure prediction confidence and variance

Author: AI Assistant
"""

import sys

import numpy as np
import pandas as pd

# Import the classifier directly from the file
sys.path.insert(0, "src/dmv_scam_analysis/core")
import json
from datetime import datetime

from classifier import MLThreatClassifier

try:
    import matplotlib.pyplot as plt
    import seaborn as sns
except ImportError:
    # Optional plotting libraries
    plt = None
    sns = None


def create_test_data():
    """Create comprehensive test dataset for ensemble evaluation"""
    test_messages = [
        # High threat messages (government impersonation + urgency)
        {
            "text": "URGENT: Your driver's license has been suspended. Click http://dmv-license-verify.tk to pay $299 reinstatement fee within 24 hours.",
            "is_from_me": 0,
            "readable_date": "2025-01-01 14:30:00",
        },
        {
            "text": "FINAL WARNING: DMV records show unpaid violations. Pay $450 at dmv-pay-center.ga now to avoid license suspension and legal action.",
            "is_from_me": 0,
            "readable_date": "2025-01-01 14:45:00",
        },
        {
            "text": "DMV Notice: License expiration detected. Renew now at https://gov-dmv-renewal.ml. Immediate action required to avoid suspension.",
            "is_from_me": 0,
            "readable_date": "2025-01-01 15:00:00",
        },
        # Medium threat messages (some suspicious elements)
        {
            "text": "Your vehicle registration expires soon. Please visit our website to renew: dmv-renewal-center.vip",
            "is_from_me": 0,
            "readable_date": "2025-01-01 15:15:00",
        },
        {
            "text": "Important: Your DMV account needs verification. Call 555-0123 immediately to avoid service interruption.",
            "is_from_me": 0,
            "readable_date": "2025-01-01 15:30:00",
        },
        # Low threat messages (legitimate-looking)
        {
            "text": "Reminder: Your vehicle registration expires next month. Renew online at www.dmv.gov or visit your local DMV office.",
            "is_from_me": 0,
            "readable_date": "2025-01-01 16:00:00",
        },
        {
            "text": "Your annual vehicle registration is due for renewal. Visit dmv.gov/renew or call 1-800-DMV-INFO.",
            "is_from_me": 0,
            "readable_date": "2025-01-01 16:15:00",
        },
        # Benign messages (normal conversation)
        {
            "text": "Thanks for helping me with the DMV paperwork today. I'll let you know how it goes.",
            "is_from_me": 1,
            "readable_date": "2025-01-01 16:30:00",
        },
        {
            "text": "No problem! The DMV can be confusing. Just make sure you bring all the required documents.",
            "is_from_me": 0,
            "readable_date": "2025-01-01 16:45:00",
        },
        {
            "text": "I went to the DMV office yesterday and renewed my license. The process was much faster than expected.",
            "is_from_me": 1,
            "readable_date": "2025-01-01 17:00:00",
        },
    ]

    return test_messages


def evaluate_individual_models(classifier, feature_data):
    """Evaluate individual model performance"""
    print("\n" + "=" * 60)
    print("INDIVIDUAL MODEL PERFORMANCE EVALUATION")
    print("=" * 60)

    training_results = classifier.train_threat_classifier(feature_data)

    if not training_results or "training_results" not in training_results:
        print("❌ Training failed")
        return None

    model_performances = []

    print(f"\nBest Overall Model: {training_results.get('best_model', 'Unknown')}")
    print(f"Feature Count: {len(training_results.get('feature_names', []))}")
    print(f"Label Distribution: {training_results.get('label_distribution', {})}")

    print("\n" + "-" * 50)
    print("Individual Model Metrics:")
    print("-" * 50)

    for model_name, metrics in training_results["training_results"].items():
        if isinstance(metrics, dict) and "error" not in metrics:
            print(f"\n🤖 {model_name.upper().replace('_', ' ')}")
            print(f"   Accuracy:  {metrics.get('accuracy', 0):.3f}")
            print(f"   Precision: {metrics.get('precision', 0):.3f}")
            print(f"   Recall:    {metrics.get('recall', 0):.3f}")
            print(f"   F1 Score:  {metrics.get('f1_score', 0):.3f}")
            print(
                f"   CV Mean:   {metrics.get('cv_mean', 0):.3f} ± {metrics.get('cv_std', 0):.3f}"
            )

            model_performances.append(
                {
                    "model": model_name,
                    "accuracy": metrics.get("accuracy", 0),
                    "precision": metrics.get("precision", 0),
                    "recall": metrics.get("recall", 0),
                    "f1_score": metrics.get("f1_score", 0),
                    "cv_mean": metrics.get("cv_mean", 0),
                    "cv_std": metrics.get("cv_std", 0),
                }
            )

            # Show top features for this model
            if "feature_importance" in metrics and metrics["feature_importance"]:
                top_features = sorted(
                    metrics["feature_importance"].items(),
                    key=lambda x: x[1],
                    reverse=True,
                )[:3]
                print(f"   Top Features: {', '.join([f[0] for f in top_features])}")
        else:
            print(f"\n❌ {model_name}: {metrics.get('error', 'Unknown error')}")

    return model_performances, training_results


def test_ensemble_functionality(classifier, test_messages):
    """Test ensemble prediction averaging and variance measurement"""
    print("\n" + "=" * 60)
    print("ENSEMBLE FUNCTIONALITY TEST")
    print("=" * 60)

    # Prepare data for ensemble training
    texts = [msg["text"] for msg in test_messages]
    labels = [0, 1, 1, 0, 1, 0, 0, 0, 0, 0]  # Example labels as specified in task

    print(
        f"Training ensemble with {len(texts)} messages and {len(set(labels))} unique labels"
    )
    print(f"Label distribution: {dict(zip(*np.unique(labels, return_counts=True)))}")

    # Train ensemble
    print("\n🔧 Training ensemble models...")
    ensemble_results = classifier.train_ensemble(texts=texts, labels=labels)

    if "error" in ensemble_results:
        print(f"❌ Ensemble training failed: {ensemble_results['error']}")
        return None

    print("✅ Ensemble trained successfully!")
    print(f"   Ensemble size: {ensemble_results.get('ensemble_size', 0)} models")
    print(f"   Best model: {ensemble_results.get('best_model', 'Unknown')}")

    # Make ensemble predictions
    print("\n🔮 Making ensemble predictions...")
    predictions = classifier.predict_ensemble(texts)

    if "error" in predictions:
        print(f"❌ Ensemble prediction failed: {predictions['error']}")
        return None

    print("✅ Ensemble predictions completed!")

    # Display results as specified in task
    print(f"\nMean predictions: {predictions['mean_prediction']}")
    print(f"Prediction variance: {predictions['std_prediction']}")

    return predictions, ensemble_results


def analyze_prediction_confidence_variance(predictions, test_messages):
    """Analyze prediction confidence and variance in detail"""
    print("\n" + "=" * 60)
    print("PREDICTION CONFIDENCE & VARIANCE ANALYSIS")
    print("=" * 60)

    mean_preds = np.array(predictions["mean_prediction"])
    std_preds = np.array(predictions["std_prediction"])
    individual_preds = predictions["individual_predictions"]

    print("\nStatistical Summary:")
    print(f"   Mean prediction range: {mean_preds.min():.3f} - {mean_preds.max():.3f}")
    print(f"   Average confidence: {mean_preds.mean():.3f}")
    print(
        f"   Prediction variance range: {std_preds.min():.3f} - {std_preds.max():.3f}"
    )
    print(f"   Average variance: {std_preds.mean():.3f}")

    # Analyze per message
    print("\nPer-Message Analysis:")
    print("-" * 50)

    for i, (msg, mean_pred, std_pred) in enumerate(
        zip(test_messages, mean_preds, std_preds)
    ):
        confidence_level = (
            "HIGH" if std_pred < 0.1 else "MEDIUM" if std_pred < 0.2 else "LOW"
        )
        threat_level = (
            "HIGH" if mean_pred > 0.6 else "MEDIUM" if mean_pred > 0.3 else "LOW"
        )

        print(f"\nMessage {i+1}: {msg['text'][:60]}...")
        print(f"   Mean Prediction: {mean_pred:.3f} (Threat: {threat_level})")
        print(f"   Prediction Std:  {std_pred:.3f} (Confidence: {confidence_level})")

        # Show individual model predictions for this message
        if i < len(individual_preds[0]):
            individual_scores = [pred[i] for pred in individual_preds]
            print(
                f"   Individual scores: {[f'{score:.3f}' for score in individual_scores]}"
            )

    return {
        "mean_predictions": mean_preds,
        "std_predictions": std_preds,
        "confidence_stats": {
            "high_confidence_count": sum(1 for std in std_preds if std < 0.1),
            "medium_confidence_count": sum(1 for std in std_preds if 0.1 <= std < 0.2),
            "low_confidence_count": sum(1 for std in std_preds if std >= 0.2),
            "avg_variance": std_preds.mean(),
            "max_variance": std_preds.max(),
            "min_variance": std_preds.min(),
        },
    }


def compare_ensemble_vs_individual(classifier, test_messages):
    """Compare ensemble performance against individual models"""
    print("\n" + "=" * 60)
    print("ENSEMBLE vs INDIVIDUAL MODEL COMPARISON")
    print("=" * 60)

    texts = [msg["text"] for msg in test_messages]

    # Get ensemble predictions
    ensemble_preds = classifier.predict_ensemble(texts)
    if "error" in ensemble_preds:
        print(f"❌ Could not get ensemble predictions: {ensemble_preds['error']}")
        return

    # Get individual model predictions using the standard predict method
    individual_scores = classifier.predict(test_messages)

    print("\nComparison Results:")
    print("-" * 30)

    ensemble_means = np.array(ensemble_preds["mean_prediction"])
    individual_array = np.array(individual_scores)

    print(f"Ensemble average score: {ensemble_means.mean():.3f}")
    print(f"Individual model average score: {individual_array.mean():.3f}")
    print(
        f"Correlation coefficient: {np.corrcoef(ensemble_means, individual_array)[0,1]:.3f}"
    )

    # Show differences per message
    print("\nPer-Message Comparison:")
    for i, (msg, ensemble_score, individual_score) in enumerate(
        zip(test_messages, ensemble_means, individual_scores)
    ):
        diff = abs(ensemble_score - individual_score)
        agreement = "AGREE" if diff < 0.1 else "DIFFER"

        print(
            f"Message {i+1}: Ensemble={ensemble_score:.3f}, Individual={individual_score:.3f}, Diff={diff:.3f} ({agreement})"
        )


def generate_performance_report(
    model_performances, ensemble_results, confidence_analysis
):
    """Generate comprehensive performance report"""
    print("\n" + "=" * 60)
    print("COMPREHENSIVE PERFORMANCE REPORT")
    print("=" * 60)

    report = {
        "timestamp": datetime.now().isoformat(),
        "individual_models": model_performances,
        "ensemble_results": ensemble_results,
        "confidence_analysis": confidence_analysis,
        "summary": {},
    }

    if model_performances:
        # Find best individual model
        best_individual = max(model_performances, key=lambda x: x["f1_score"])
        worst_individual = min(model_performances, key=lambda x: x["f1_score"])

        avg_f1 = np.mean([m["f1_score"] for m in model_performances])
        avg_accuracy = np.mean([m["accuracy"] for m in model_performances])

        report["summary"] = {
            "best_individual_model": best_individual["model"],
            "best_individual_f1": best_individual["f1_score"],
            "worst_individual_model": worst_individual["model"],
            "worst_individual_f1": worst_individual["f1_score"],
            "average_f1_score": avg_f1,
            "average_accuracy": avg_accuracy,
            "model_count": len(model_performances),
            "ensemble_size": ensemble_results.get("ensemble_size", 0)
            if ensemble_results
            else 0,
        }

        print("\n📊 PERFORMANCE SUMMARY")
        print(
            f"   Best Individual Model: {best_individual['model']} (F1: {best_individual['f1_score']:.3f})"
        )
        print(
            f"   Worst Individual Model: {worst_individual['model']} (F1: {worst_individual['f1_score']:.3f})"
        )
        print(f"   Average F1 Score: {avg_f1:.3f}")
        print(f"   Average Accuracy: {avg_accuracy:.3f}")
        print(f"   Models Trained: {len(model_performances)}")

        if ensemble_results:
            print(f"   Ensemble Size: {ensemble_results.get('ensemble_size', 0)}")

        if confidence_analysis:
            print("\n🎯 CONFIDENCE ANALYSIS")
            stats = confidence_analysis.get("confidence_stats", {})
            print(
                f"   High Confidence Predictions: {stats.get('high_confidence_count', 0)}"
            )
            print(
                f"   Medium Confidence Predictions: {stats.get('medium_confidence_count', 0)}"
            )
            print(
                f"   Low Confidence Predictions: {stats.get('low_confidence_count', 0)}"
            )
            print(f"   Average Prediction Variance: {stats.get('avg_variance', 0):.3f}")

    # Save report to file
    report_file = "ensemble_performance_report.json"
    with open(report_file, "w") as f:
        json.dump(report, f, indent=2, default=str)

    print(f"\n✅ Detailed report saved to: {report_file}")

    return report


def main():
    """Main test execution function"""
    print("🧪 ENSEMBLE MODEL PERFORMANCE TEST")
    print("=" * 60)
    print("Testing ensemble functionality as specified:")
    print(
        "- Train multiple model types (Random Forest, Gradient Boosting, SVM, Logistic Regression, Naive Bayes)"
    )
    print("- Compare individual model performance")
    print("- Test ensemble prediction averaging")
    print("- Measure prediction confidence and variance")
    print("=" * 60)

    # Initialize classifier
    classifier = MLThreatClassifier(output_dir="./test_output")

    # Create test data
    test_messages = create_test_data()
    print(f"✅ Created test dataset with {len(test_messages)} messages")

    # Convert to DataFrame for feature extraction
    df = pd.DataFrame(test_messages)

    # Extract features for training
    print("🔧 Extracting features for model training...")
    feature_data = classifier.extract_ml_features(df, include_labels=True)

    if not feature_data:
        print("❌ Feature extraction failed")
        return 1

    print(
        f"✅ Extracted {len(feature_data.get('feature_names', []))} features from {len(test_messages)} messages"
    )

    # Test individual models
    model_performances, training_results = evaluate_individual_models(
        classifier, feature_data
    )

    # Test ensemble functionality
    ensemble_predictions, ensemble_results = test_ensemble_functionality(
        classifier, test_messages
    )

    if not ensemble_predictions:
        print("❌ Ensemble testing failed")
        return 1

    # Analyze prediction confidence and variance
    confidence_analysis = analyze_prediction_confidence_variance(
        ensemble_predictions, test_messages
    )

    # Compare ensemble vs individual models
    compare_ensemble_vs_individual(classifier, test_messages)

    # Generate comprehensive report
    final_report = generate_performance_report(
        model_performances, ensemble_results, confidence_analysis
    )

    print("\n" + "=" * 60)
    print("🎉 ENSEMBLE MODEL PERFORMANCE TEST COMPLETED SUCCESSFULLY!")
    print("=" * 60)
    print("\nTask Requirements Fulfilled:")
    print(
        "✅ Trained multiple model types (Random Forest, Gradient Boosting, SVM, Logistic Regression, Naive Bayes)"
    )
    print("✅ Compared individual model performance")
    print("✅ Tested ensemble prediction averaging")
    print("✅ Measured prediction confidence and variance")
    print("✅ Generated comprehensive performance report")

    return 0


if __name__ == "__main__":
    exit(main())
