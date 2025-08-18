"""Integration tests for machine learning pipeline components."""

import numpy as np
import pandas as pd
import pytest

from dmv_scam_analysis.analysis.behavioral import BehavioralAnalyzer
from dmv_scam_analysis.analysis.sentiment import AdvancedNLPAnalyzer as NLPAnalyzer
from dmv_scam_analysis.core.classifier import MLThreatClassifier as ThreatClassifier
from dmv_scam_analysis.utils.config_manager import ConfigManager


@pytest.fixture
def training_data():
    """Generate synthetic training data for ML models."""
    np.random.seed(42)
    n_samples = 1000

    # Generate feature data
    text_features = [
        "urgent payment required",
        "license expiration notice",
        "dmv registration renewal",
        "verify your information",
        "click here to pay",
    ]

    data = []
    for _ in range(n_samples):
        n_features = np.random.randint(1, 4)
        features = np.random.choice(text_features, n_features, replace=False)
        text = " ".join(features)

        # Add some randomization
        if np.random.random() > 0.5:
            text = text.upper()

        # Add noise
        if np.random.random() > 0.7:
            text += " " + "".join(
                np.random.choice(list("abcdefghijklmnopqrstuvwxyz"), 10)
            )

        # Generate metadata
        sample = {
            "text": text,
            "source": np.random.choice(["email", "sms", "web"]),
            "metadata": {
                "ip": f"192.168.{np.random.randint(1,255)}.{np.random.randint(1,255)}",
                "timestamp": pd.Timestamp.now().isoformat(),
                "domain": f"example{np.random.randint(1,100)}.com",
            },
        }

        # Label based on features
        is_scam = (
            any(f in text.lower() for f in ["urgent", "click", "verify"])
            and np.random.random() > 0.2
        )
        sample["label"] = 1 if is_scam else 0

        data.append(sample)

    return pd.DataFrame(data)


@pytest.fixture
def ml_pipeline_components():
    """Initialize ML pipeline components."""
    return {
        "classifier": ThreatClassifier(),
        "behavioral_analyzer": BehavioralAnalyzer(),
        "nlp_analyzer": NLPAnalyzer(),
        "config": ConfigManager(),
    }


def test_end_to_end_training(training_data, ml_pipeline_components):
    """Test end-to-end training pipeline."""
    # Split data
    train_idx = np.random.choice(
        len(training_data), int(0.8 * len(training_data)), replace=False
    )
    train_data = training_data.iloc[train_idx]
    test_data = training_data.iloc[~training_data.index.isin(train_idx)]

    # Train classifier
    classifier = ml_pipeline_components["classifier"]
    classifier.train(texts=train_data["text"].values, labels=train_data["label"].values)

    # Validate training
    assert hasattr(classifier, "model")
    assert classifier.model is not None

    # Test prediction
    predictions = classifier.predict(test_data["text"].values)
    assert len(predictions) == len(test_data)
    assert all(0 <= p <= 1 for p in predictions)

    # Calculate metrics
    accuracy = np.mean(np.round(predictions) == test_data["label"].values)
    assert accuracy > 0.7  # Should achieve at least 70% accuracy


def test_feature_extraction(training_data, ml_pipeline_components):
    """Test feature extraction pipeline."""
    nlp_analyzer = ml_pipeline_components["nlp_analyzer"]

    # Extract features
    features = nlp_analyzer.extract_features(training_data["text"].values[:10])

    # Validate feature extraction
    assert isinstance(features, np.ndarray)
    assert features.shape[0] == 10
    assert features.shape[1] > 0  # Should have multiple features per sample

    # Test feature importance
    importance = nlp_analyzer.get_feature_importance(
        features, training_data["label"].values[:10]
    )
    assert len(importance) == features.shape[1]
    assert all(isinstance(x, (int, float)) for x in importance)


def test_behavioral_pattern_detection(training_data, ml_pipeline_components):
    """Test behavioral pattern detection."""
    analyzer = ml_pipeline_components["behavioral_analyzer"]

    # Analyze patterns
    patterns = analyzer.detect_patterns(training_data.to_dict("records"))

    # Validate pattern detection
    assert "temporal_patterns" in patterns
    assert "source_patterns" in patterns
    assert "threat_clusters" in patterns

    # Validate temporal patterns
    assert isinstance(patterns["temporal_patterns"], dict)
    assert "hourly_distribution" in patterns["temporal_patterns"]
    assert "daily_distribution" in patterns["temporal_patterns"]

    # Validate threat clusters
    assert isinstance(patterns["threat_clusters"], dict)
    assert len(patterns["threat_clusters"]) > 0
    assert all(
        isinstance(cluster, dict) for cluster in patterns["threat_clusters"].values()
    )


def test_model_persistence(tmp_path, ml_pipeline_components):
    """Test model saving and loading."""
    classifier = ml_pipeline_components["classifier"]

    # Save model
    model_path = tmp_path / "model.pkl"
    classifier.save_model(model_path)
    assert model_path.exists()

    # Load model
    new_classifier = ThreatClassifier()
    new_classifier.load_model(model_path)

    # Compare predictions
    test_texts = [
        "Urgent: Your license is expiring",
        "Normal DMV notification",
        "Click here to verify account",
    ]

    original_predictions = classifier.predict(test_texts)
    loaded_predictions = new_classifier.predict(test_texts)
    np.testing.assert_array_almost_equal(original_predictions, loaded_predictions)


def test_incremental_learning(training_data, ml_pipeline_components):
    """Test incremental learning capabilities."""
    classifier = ml_pipeline_components["classifier"]

    # Initial training
    initial_data = training_data.iloc[:800]
    classifier.train(
        texts=initial_data["text"].values, labels=initial_data["label"].values
    )

    initial_predictions = classifier.predict(training_data.iloc[800:]["text"].values)

    # Incremental update
    new_data = training_data.iloc[800:]
    classifier.update_model(
        texts=new_data["text"].values, labels=new_data["label"].values
    )

    updated_predictions = classifier.predict(new_data["text"].values)

    # Verify model improvement
    initial_accuracy = np.mean(
        np.round(initial_predictions) == new_data["label"].values
    )
    updated_accuracy = np.mean(
        np.round(updated_predictions) == new_data["label"].values
    )
    assert updated_accuracy >= initial_accuracy


def test_model_explainability(training_data, ml_pipeline_components):
    """Test model explainability features."""
    classifier = ml_pipeline_components["classifier"]

    # Train model
    classifier.train(
        texts=training_data["text"].values, labels=training_data["label"].values
    )

    # Get feature explanations
    test_text = "Urgent: Click here to verify your license status"
    explanation = classifier.explain_prediction(test_text)

    # Validate explanation
    assert isinstance(explanation, dict)
    assert "feature_importance" in explanation
    assert "decision_path" in explanation
    assert "confidence_score" in explanation

    # Validate feature importance
    assert len(explanation["feature_importance"]) > 0
    assert all(
        isinstance(score, float) for score in explanation["feature_importance"].values()
    )
    assert abs(sum(explanation["feature_importance"].values()) - 1.0) < 1e-5


def test_ensemble_predictions(training_data, ml_pipeline_components):
    """Test ensemble prediction methods."""
    classifier = ml_pipeline_components["classifier"]

    # Train multiple models
    _models = classifier.train_ensemble(
        texts=training_data["text"].values,
        labels=training_data["label"].values,
        n_models=3,
    )

    # Get ensemble predictions
    test_texts = training_data["text"].values[:10]
    ensemble_predictions = classifier.predict_ensemble(test_texts)

    # Validate ensemble predictions
    assert isinstance(ensemble_predictions, dict)
    assert "mean_prediction" in ensemble_predictions
    assert "std_prediction" in ensemble_predictions
    assert "individual_predictions" in ensemble_predictions

    # Check statistical properties
    assert len(ensemble_predictions["mean_prediction"]) == len(test_texts)
    assert len(ensemble_predictions["std_prediction"]) == len(test_texts)
    assert all(0 <= p <= 1 for p in ensemble_predictions["mean_prediction"])
    assert all(0 <= s for s in ensemble_predictions["std_prediction"])


def test_cross_validation(training_data, ml_pipeline_components):
    """Test cross-validation performance."""
    from sklearn.model_selection import KFold

    classifier = ml_pipeline_components["classifier"]

    kf = KFold(n_splits=5, shuffle=True, random_state=42)
    scores = []

    for train_idx, val_idx in kf.split(training_data):
        # Train on fold
        train_fold = training_data.iloc[train_idx]
        val_fold = training_data.iloc[val_idx]

        classifier.train(
            texts=train_fold["text"].values, labels=train_fold["label"].values
        )

        # Validate on fold
        predictions = classifier.predict(val_fold["text"].values)
        accuracy = np.mean(np.round(predictions) == val_fold["label"].values)
        scores.append(accuracy)

    # Check cross-validation results
    mean_cv_score = np.mean(scores)
    std_cv_score = np.std(scores)

    assert mean_cv_score > 0.7  # Should maintain good performance across folds
    assert std_cv_score < 0.1  # Should be consistent across folds
