"""Model management system for production deployment."""

import hashlib
import json
import logging
import os
import pickle
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class ModelManager:
    """Advanced model management with versioning and deployment controls."""

    def __init__(self, model_dir: str = "models"):
        """
        Initialize model manager.

        Args:
            model_dir: Directory to store models and metadata
        """
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(exist_ok=True)
        self.metadata_file = self.model_dir / "model_metadata.json"
        self.active_model_file = self.model_dir / "active_model.json"

        # Load existing metadata
        self.metadata = self._load_metadata()

    def save_model(
        self,
        model: Any,
        model_name: str,
        version: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        performance_metrics: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Save a model with versioning and metadata.

        Args:
            model: The trained model object
            model_name: Name identifier for the model
            version: Version string (auto-generated if None)
            metadata: Additional metadata
            performance_metrics: Model performance metrics

        Returns:
            Model ID for the saved model
        """
        try:
            # Generate version if not provided
            if version is None:
                version = datetime.now().strftime("%Y%m%d_%H%M%S")

            model_id = f"{model_name}_v{version}"
            model_path = self.model_dir / f"{model_id}.pkl"

            # Save the model
            with open(model_path, "wb") as f:
                pickle.dump(model, f)

            # Calculate model hash for integrity
            model_hash = self._calculate_file_hash(model_path)

            # Store metadata
            model_info = {
                "model_id": model_id,
                "model_name": model_name,
                "version": version,
                "file_path": str(model_path),
                "file_size": os.path.getsize(model_path),
                "file_hash": model_hash,
                "created_at": datetime.now().isoformat(),
                "metadata": metadata or {},
                "performance_metrics": performance_metrics or {},
                "status": "trained",
            }

            self.metadata[model_id] = model_info
            self._save_metadata()

            logger.info(f"Model {model_id} saved successfully")
            return model_id

        except Exception as e:
            logger.error(f"Failed to save model {model_name}: {e}")
            raise

    def load_model(self, model_id: str) -> Tuple[Any, Dict]:
        """Load a model by ID."""
        if model_id not in self.metadata:
            raise ValueError(f"Model {model_id} not found")

        model_info = self.metadata[model_id]
        model_path = Path(model_info["file_path"])

        if not model_path.exists():
            raise FileNotFoundError(f"Model file not found: {model_path}")

        # Verify integrity
        current_hash = self._calculate_file_hash(model_path)
        if current_hash != model_info["file_hash"]:
            logger.warning(f"Model file integrity check failed for {model_id}")

        try:
            with open(model_path, "rb") as f:
                model = pickle.load(f)

            logger.info(f"Model {model_id} loaded successfully")
            return model, model_info

        except Exception as e:
            logger.error(f"Failed to load model {model_id}: {e}")
            raise

    def set_active_model(self, model_id: str) -> None:
        """Set a model as the active production model."""
        if model_id not in self.metadata:
            raise ValueError(f"Model {model_id} not found")

        # Validate model can be loaded
        try:
            model, info = self.load_model(model_id)
        except Exception as e:
            raise ValueError(f"Cannot activate model {model_id}: {e}")

        active_info = {
            "model_id": model_id,
            "activated_at": datetime.now().isoformat(),
            "activated_by": "system",
        }

        with open(self.active_model_file, "w") as f:
            json.dump(active_info, f, indent=2)

        # Update model status
        self.metadata[model_id]["status"] = "active"
        self._save_metadata()

        logger.info(f"Model {model_id} set as active")

    def get_active_model(self) -> Tuple[Any, Dict, str]:
        """Get the current active model."""
        if not self.active_model_file.exists():
            raise ValueError("No active model set")

        with open(self.active_model_file, "r") as f:
            active_info = json.load(f)

        model_id = active_info["model_id"]
        model, model_info = self.load_model(model_id)

        return model, model_info, model_id

    def list_models(self, model_name: Optional[str] = None) -> List[Dict]:
        """List all available models."""
        models = list(self.metadata.values())

        if model_name:
            models = [m for m in models if m["model_name"] == model_name]

        # Sort by creation date (newest first)
        models.sort(key=lambda x: x["created_at"], reverse=True)
        return models

    def delete_model(self, model_id: str, force: bool = False) -> None:
        """Delete a model and its files."""
        if model_id not in self.metadata:
            raise ValueError(f"Model {model_id} not found")

        model_info = self.metadata[model_id]

        # Prevent deletion of active model without force
        if not force and model_info.get("status") == "active":
            raise ValueError(
                f"Cannot delete active model {model_id} without force=True"
            )

        # Delete model file
        model_path = Path(model_info["file_path"])
        if model_path.exists():
            os.remove(model_path)

        # Remove from metadata
        del self.metadata[model_id]
        self._save_metadata()

        logger.info(f"Model {model_id} deleted")

    def get_model_performance(self, model_id: str) -> Dict[str, Any]:
        """Get performance metrics for a model."""
        if model_id not in self.metadata:
            raise ValueError(f"Model {model_id} not found")

        metrics = self.metadata[model_id].get("performance_metrics", {})
        # Ensure a dict is returned
        return dict(metrics)

    def update_model_metadata(self, model_id: str, metadata_updates: Dict) -> None:
        """Update metadata for a model."""
        if model_id not in self.metadata:
            raise ValueError(f"Model {model_id} not found")

        self.metadata[model_id]["metadata"].update(metadata_updates)
        self.metadata[model_id]["updated_at"] = datetime.now().isoformat()
        self._save_metadata()

        logger.info(f"Metadata updated for model {model_id}")

    def cleanup_old_models(self, keep_count: int = 5) -> List[str]:
        """Clean up old model versions, keeping only the most recent."""
        deleted_models: List[str] = []

        # Group models by name
        model_groups: Dict[str, List[Tuple[str, Dict[str, Any]]]] = {}
        for model_id, info in self.metadata.items():
            name = info["model_name"]
            if name not in model_groups:
                model_groups[name] = []
            model_groups[name].append((model_id, info))

        # For each model group, keep only the newest versions
        for model_name, models in model_groups.items():
            # Sort by creation date (newest first)
            models.sort(key=lambda x: x[1]["created_at"], reverse=True)

            # Delete old versions beyond keep_count
            for model_id, info in models[keep_count:]:
                if info.get("status") != "active":  # Never delete active models
                    try:
                        self.delete_model(model_id)
                        deleted_models.append(model_id)
                    except Exception as e:
                        logger.error(f"Failed to delete model {model_id}: {e}")

        logger.info(f"Cleaned up {len(deleted_models)} old models")
        return deleted_models

    def _load_metadata(self) -> Dict[str, Any]:
        """Load model metadata from file."""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, "r") as f:
                    data = json.load(f)
                    return dict(data)
            except Exception as e:
                logger.error(f"Failed to load metadata: {e}")
                return {}
        return {}

    def _save_metadata(self) -> None:
        """Save model metadata to file."""
        try:
            with open(self.metadata_file, "w") as f:
                json.dump(self.metadata, f, indent=2, sort_keys=True)
        except Exception as e:
            logger.error(f"Failed to save metadata: {e}")
            raise

    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

    def export_model_info(self, model_id: Optional[str] = None) -> Dict:
        """Export model information for deployment or backup."""
        if model_id:
            if model_id not in self.metadata:
                raise ValueError(f"Model {model_id} not found")
            return {model_id: self.metadata[model_id]}
        else:
            return dict(self.metadata)
