"""Model management system for production deployment."""

import os
import pickle
import json
import hashlib
from datetime import datetime
from typing import Dict, Optional, List, Tuple, Any
from pathlib import Path
import logging

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
        version: str = None,
        metadata: Dict = None,
        performance_metrics: Dict = None
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
            with open(model_path, 'wb') as f:
                pickle.dump(model, f)
            
            # Calculate model hash for integrity
            model_hash = self._calculate_file_hash(model_path)
            
            # Store metadata
            model_info = {
                'model_id': model_id,
                'model_name': model_name,
                'version': version,
                'file_path': str(model_path),
                'file_size': os.path.getsize(model_path),
                'file_hash': model_hash,
                'created_at': datetime.now().isoformat(),
                'metadata': metadata or {},
                'performance_metrics': performance_metrics or {},
                'status': 'trained'
            }\n            \n            self.metadata[model_id] = model_info\n            self._save_metadata()\n            \n            logger.info(f\"Model {model_id} saved successfully\")\n            return model_id\n            \n        except Exception as e:\n            logger.error(f\"Failed to save model {model_name}: {e}\")\n            raise\n    \n    def load_model(self, model_id: str) -> Tuple[Any, Dict]:\n        \"\"\"Load a model by ID.\"\"\"\n        if model_id not in self.metadata:\n            raise ValueError(f\"Model {model_id} not found\")\n        \n        model_info = self.metadata[model_id]\n        model_path = Path(model_info['file_path'])\n        \n        if not model_path.exists():\n            raise FileNotFoundError(f\"Model file not found: {model_path}\")\n        \n        # Verify integrity\n        current_hash = self._calculate_file_hash(model_path)\n        if current_hash != model_info['file_hash']:\n            logger.warning(f\"Model file integrity check failed for {model_id}\")\n        \n        try:\n            with open(model_path, 'rb') as f:\n                model = pickle.load(f)\n            \n            logger.info(f\"Model {model_id} loaded successfully\")\n            return model, model_info\n            \n        except Exception as e:\n            logger.error(f\"Failed to load model {model_id}: {e}\")\n            raise\n    \n    def set_active_model(self, model_id: str) -> None:\n        \"\"\"Set a model as the active production model.\"\"\"\n        if model_id not in self.metadata:\n            raise ValueError(f\"Model {model_id} not found\")\n        \n        # Validate model can be loaded\n        try:\n            model, info = self.load_model(model_id)\n        except Exception as e:\n            raise ValueError(f\"Cannot activate model {model_id}: {e}\")\n        \n        active_info = {\n            'model_id': model_id,\n            'activated_at': datetime.now().isoformat(),\n            'activated_by': 'system'\n        }\n        \n        with open(self.active_model_file, 'w') as f:\n            json.dump(active_info, f, indent=2)\n        \n        # Update model status\n        self.metadata[model_id]['status'] = 'active'\n        self._save_metadata()\n        \n        logger.info(f\"Model {model_id} set as active\")\n    \n    def get_active_model(self) -> Tuple[Any, Dict, str]:\n        \"\"\"Get the current active model.\"\"\"\n        if not self.active_model_file.exists():\n            raise ValueError(\"No active model set\")\n        \n        with open(self.active_model_file, 'r') as f:\n            active_info = json.load(f)\n        \n        model_id = active_info['model_id']\n        model, model_info = self.load_model(model_id)\n        \n        return model, model_info, model_id\n    \n    def list_models(self, model_name: str = None) -> List[Dict]:\n        \"\"\"List all available models.\"\"\"\n        models = list(self.metadata.values())\n        \n        if model_name:\n            models = [m for m in models if m['model_name'] == model_name]\n        \n        # Sort by creation date (newest first)\n        models.sort(key=lambda x: x['created_at'], reverse=True)\n        return models\n    \n    def delete_model(self, model_id: str, force: bool = False) -> None:\n        \"\"\"Delete a model and its files.\"\"\"\n        if model_id not in self.metadata:\n            raise ValueError(f\"Model {model_id} not found\")\n        \n        model_info = self.metadata[model_id]\n        \n        # Prevent deletion of active model without force\n        if not force and model_info.get('status') == 'active':\n            raise ValueError(f\"Cannot delete active model {model_id} without force=True\")\n        \n        # Delete model file\n        model_path = Path(model_info['file_path'])\n        if model_path.exists():\n            os.remove(model_path)\n        \n        # Remove from metadata\n        del self.metadata[model_id]\n        self._save_metadata()\n        \n        logger.info(f\"Model {model_id} deleted\")\n    \n    def get_model_performance(self, model_id: str) -> Dict:\n        \"\"\"Get performance metrics for a model.\"\"\"\n        if model_id not in self.metadata:\n            raise ValueError(f\"Model {model_id} not found\")\n        \n        return self.metadata[model_id].get('performance_metrics', {})\n    \n    def update_model_metadata(self, model_id: str, metadata_updates: Dict) -> None:\n        \"\"\"Update metadata for a model.\"\"\"\n        if model_id not in self.metadata:\n            raise ValueError(f\"Model {model_id} not found\")\n        \n        self.metadata[model_id]['metadata'].update(metadata_updates)\n        self.metadata[model_id]['updated_at'] = datetime.now().isoformat()\n        self._save_metadata()\n        \n        logger.info(f\"Metadata updated for model {model_id}\")\n    \n    def cleanup_old_models(self, keep_count: int = 5) -> List[str]:\n        \"\"\"Clean up old model versions, keeping only the most recent.\"\"\"\n        deleted_models = []\n        \n        # Group models by name\n        model_groups = {}\n        for model_id, info in self.metadata.items():\n            name = info['model_name']\n            if name not in model_groups:\n                model_groups[name] = []\n            model_groups[name].append((model_id, info))\n        \n        # For each model group, keep only the newest versions\n        for model_name, models in model_groups.items():\n            # Sort by creation date (newest first)\n            models.sort(key=lambda x: x[1]['created_at'], reverse=True)\n            \n            # Delete old versions beyond keep_count\n            for model_id, info in models[keep_count:]:\n                if info.get('status') != 'active':  # Never delete active models\n                    try:\n                        self.delete_model(model_id)\n                        deleted_models.append(model_id)\n                    except Exception as e:\n                        logger.error(f\"Failed to delete model {model_id}: {e}\")\n        \n        logger.info(f\"Cleaned up {len(deleted_models)} old models\")\n        return deleted_models\n    \n    def _load_metadata(self) -> Dict:\n        \"\"\"Load model metadata from file.\"\"\"\n        if self.metadata_file.exists():\n            try:\n                with open(self.metadata_file, 'r') as f:\n                    return json.load(f)\n            except Exception as e:\n                logger.error(f\"Failed to load metadata: {e}\")\n                return {}\n        return {}\n    \n    def _save_metadata(self) -> None:\n        \"\"\"Save model metadata to file.\"\"\"\n        try:\n            with open(self.metadata_file, 'w') as f:\n                json.dump(self.metadata, f, indent=2, sort_keys=True)\n        except Exception as e:\n            logger.error(f\"Failed to save metadata: {e}\")\n            raise\n    \n    def _calculate_file_hash(self, file_path: Path) -> str:\n        \"\"\"Calculate SHA-256 hash of a file.\"\"\"\n        sha256_hash = hashlib.sha256()\n        with open(file_path, 'rb') as f:\n            for chunk in iter(lambda: f.read(4096), b\"\"):\n                sha256_hash.update(chunk)\n        return sha256_hash.hexdigest()\n    \n    def export_model_info(self, model_id: str = None) -> Dict:\n        \"\"\"Export model information for deployment or backup.\"\"\"\n        if model_id:\n            if model_id not in self.metadata:\n                raise ValueError(f\"Model {model_id} not found\")\n            return {model_id: self.metadata[model_id]}\n        else:\n            return dict(self.metadata)
