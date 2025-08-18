"""
Model Trainer for DMV Scam Analysis
"""

import json
import logging
import pickle
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

logger = logging.getLogger(__name__)


class ModelTrainer:
    """
    Trains machine learning models for threat detection and text classification
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize the model trainer

        Args:
            config: Configuration object with ML training settings
        """
        self.config = config
        self.models: Dict[str, Any] = {}
        self.vectorizers: Dict[str, Any] = {}

    def train_classifier(
        self, data_path: str, output_path: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Train a text classification model for threat detection

        Args:
            data_path: Path to training data
            output_path: Path to save trained model

        Returns:
            dict: Training results and metrics
        """
        logger.info(f"🎓 Training classifier with data from {data_path}")

        # Load and prepare data
        data = self._load_training_data(data_path)
        if not data:
            logger.error("❌ No training data available")
            return None

        # Prepare features and labels
        X, y = self._prepare_classification_data(data)

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        # Create pipeline
        pipeline = Pipeline(
            [
                (
                    "vectorizer",
                    TfidfVectorizer(max_features=5000, stop_words="english"),
                ),
                ("classifier", LogisticRegression(random_state=42, max_iter=1000)),
            ]
        )

        # Train model
        logger.info("🔧 Training classifier model...")
        pipeline.fit(X_train, y_train)

        # Evaluate model
        y_pred = pipeline.predict(X_test)
        report = classification_report(y_test, y_pred, output_dict=True)

        # Save model
        if output_path:
            model_path = Path(output_path)
            model_path.parent.mkdir(parents=True, exist_ok=True)

            with open(model_path, "wb") as f:
                pickle.dump(pipeline, f)

            logger.info(f"💾 Model saved to {model_path}")

        results = {
            "model_type": "classifier",
            "training_samples": len(X_train),
            "test_samples": len(X_test),
            "accuracy": report["accuracy"],
            "classification_report": report,
            "training_timestamp": datetime.now().isoformat(),
        }

        logger.info("✅ Classification model trained successfully")
        logger.info(f"📊 Accuracy: {report['accuracy']:.3f}")

        return results

    def train_embeddings(
        self, data_path: str, output_path: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Train text embeddings model

        Args:
            data_path: Path to training data
            output_path: Path to save trained embeddings

        Returns:
            dict: Training results and metrics
        """
        logger.info(f"🎓 Training embeddings with data from {data_path}")

        # Load data
        data = self._load_training_data(data_path)
        if not data:
            logger.error("❌ No training data available")
            return None

        # Prepare text data
        texts = []
        for item in data:
            text = item.get("message", item.get("text", ""))
            if text:
                texts.append(text)

        # Create TF-IDF embeddings as a simple baseline
        vectorizer = TfidfVectorizer(max_features=768, stop_words="english")
        embeddings = vectorizer.fit_transform(texts)

        # Save embeddings and vectorizer
        if output_path:
            model_path = Path(output_path)
            model_path.parent.mkdir(parents=True, exist_ok=True)

            embedding_data = {
                "vectorizer": vectorizer,
                "embeddings": embeddings,
                "vocabulary": vectorizer.get_feature_names_out(),
                "training_timestamp": datetime.now().isoformat(),
            }

            with open(model_path, "wb") as f:
                pickle.dump(embedding_data, f)

            logger.info(f"💾 Embeddings saved to {model_path}")

        results = {
            "model_type": "embeddings",
            "num_texts": len(texts),
            "embedding_dimension": embeddings.shape[1],
            "vocabulary_size": len(vectorizer.vocabulary_),
            "training_timestamp": datetime.now().isoformat(),
        }

        logger.info("✅ Embeddings trained successfully")
        logger.info(f"📊 Dimension: {embeddings.shape[1]}")

        return results

    def _load_training_data(self, data_path: str) -> List[Dict[str, Any]]:
        """Load training data from JSON file"""
        try:
            with open(data_path, "r") as f:
                data = json.load(f)

            if isinstance(data, list):
                return data
            else:
                return [data]

        except Exception as e:
            logger.error(f"❌ Error loading training data: {e}")
            return []

    def _prepare_classification_data(
        self, data: List[Dict[str, Any]]
    ) -> Tuple[List[str], List[int]]:
        """Prepare data for classification training"""
        texts = []
        labels = []

        for item in data:
            # Try both 'message' and 'text' fields
            text = item.get("message", item.get("text", ""))
            if not text:
                continue

            texts.append(text)

            # Use provided labels if available, otherwise use heuristic
            if "label" in item:
                # Map string labels to integers
                label_map = {"scam": 1, "legitimate": 0, "threat": 1, "safe": 0}
                label = label_map.get(item["label"], 0)
            else:
                # Simple heuristic: messages with threat keywords are labeled as threats
                threat_keywords = [
                    "urgent",
                    "penalty",
                    "suspend",
                    "arrest",
                    "legal action",
                    "fine",
                ]
                label = (
                    1
                    if any(keyword in text.lower() for keyword in threat_keywords)
                    else 0
                )

            labels.append(label)

        return texts, labels

    def load_model(self, model_path: str) -> Any:
        """Load a trained model"""
        try:
            with open(model_path, "rb") as f:
                model = pickle.load(f)

            logger.info(f"📥 Model loaded from {model_path}")
            return model

        except Exception as e:
            logger.error(f"❌ Error loading model: {e}")
            return None

    def predict(self, model: Any, texts: Sequence[str]) -> List[Dict[str, Any]]:
        """Make predictions using a trained model"""
        if not model or not texts:
            return []

        try:
            predictions = model.predict(texts)
            probabilities = model.predict_proba(texts)

            results = []
            for i, text in enumerate(texts):
                result = {
                    "text": text,
                    "prediction": int(predictions[i]),
                    "probability": float(probabilities[i].max()),
                    "confidence": float(probabilities[i].max()),
                    "timestamp": datetime.now().isoformat(),
                }
                results.append(result)

            return results

        except Exception as e:
            logger.error(f"❌ Error making predictions: {e}")
            return []
