#!/usr/bin/env python3
"""
Data versioning script for DMV scam analysis project.
Handles dataset versioning and maintains data lineage.
"""

import pandas as pd
import numpy as np
from pathlib import Path
import logging
import json
import yaml
import shutil
from datetime import datetime
import hashlib
from typing import Dict, List, Optional
import os

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DataVersionManager:
    """Class for managing dataset versions and lineage."""
    
    def __init__(self, base_path: str = "data"):
        """Initialize the version manager."""
        self.base_path = Path(base_path)
        self.versions_file = self.base_path / "versions.json"
        self.versions = self._load_versions()
        
    def _load_versions(self) -> dict:
        """Load version history from JSON file."""
        if self.versions_file.exists():
            with open(self.versions_file, 'r') as f:
                return json.load(f)
        return {"datasets": {}}
        
    def _save_versions(self):
        """Save version history to JSON file."""
        with open(self.versions_file, 'w') as f:
            json.dump(self.versions, f, indent=2)
            
    def _calculate_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def create_version(self, 
                      dataset_name: str,
                      file_path: str,
                      version_notes: str = "",
                      parent_version: Optional[str] = None) -> str:
        """
        Create a new version of a dataset.
        
        Args:
            dataset_name: Name of the dataset
            file_path: Path to the dataset file
            version_notes: Notes about this version
            parent_version: Hash of the parent version if applicable
            
        Returns:
            Version hash string
        """
        # Calculate file hash
        file_hash = self._calculate_hash(file_path)
        
        # Create version info
        version_info = {
            "hash": file_hash,
            "timestamp": datetime.now().isoformat(),
            "file_path": file_path,
            "notes": version_notes,
            "parent_version": parent_version,
            "creator": os.getenv("USER", "unknown")
        }
        
        # Update versions dictionary
        if dataset_name not in self.versions["datasets"]:
            self.versions["datasets"][dataset_name] = {"versions": []}
            
        self.versions["datasets"][dataset_name]["versions"].append(version_info)
        
        # Save updated versions
        self._save_versions()
        
        # Create backup copy
        backup_path = self.base_path / "backup" / f"{dataset_name}_{file_hash[:8]}.csv"
        shutil.copy2(file_path, backup_path)
        
        return file_hash
    
    def get_version_info(self, dataset_name: str, version_hash: str) -> Optional[Dict]:
        """
        Get information about a specific version.
        
        Args:
            dataset_name: Name of the dataset
            version_hash: Hash of the version to retrieve
            
        Returns:
            Version information dictionary or None if not found
        """
        if dataset_name not in self.versions["datasets"]:
            return None
            
        for version in self.versions["datasets"][dataset_name]["versions"]:
            if version["hash"].startswith(version_hash):
                return version
                
        return None
    
    def list_versions(self, dataset_name: str) -> List[Dict]:
        """
        List all versions of a dataset.
        
        Args:
            dataset_name: Name of the dataset
            
        Returns:
            List of version information dictionaries
        """
        if dataset_name not in self.versions["datasets"]:
            return []
            
        return self.versions["datasets"][dataset_name]["versions"]
    
    def restore_version(self, dataset_name: str, version_hash: str, output_path: str) -> bool:
        """
        Restore a specific version of a dataset.
        
        Args:
            dataset_name: Name of the dataset
            version_hash: Hash of the version to restore
            output_path: Path where to restore the file
            
        Returns:
            True if successful, False otherwise
        """
        version_info = self.get_version_info(dataset_name, version_hash)
        if not version_info:
            logger.error(f"Version {version_hash} not found for dataset {dataset_name}")
            return False
            
        backup_path = self.base_path / "backup" / f"{dataset_name}_{version_info['hash'][:8]}.csv"
        if not backup_path.exists():
            logger.error(f"Backup file not found: {backup_path}")
            return False
            
        try:
            shutil.copy2(backup_path, output_path)
            logger.info(f"Restored version {version_hash} to {output_path}")
            return True
        except Exception as e:
            logger.error(f"Error restoring version: {e}")
            return False
    
    def get_lineage(self, dataset_name: str, version_hash: str) -> List[Dict]:
        """
        Get the lineage (history) of a specific version.
        
        Args:
            dataset_name: Name of the dataset
            version_hash: Hash of the version to trace
            
        Returns:
            List of version information dictionaries in order of lineage
        """
        lineage = []
        current_version = version_hash
        
        while current_version:
            version_info = self.get_version_info(dataset_name, current_version)
            if not version_info:
                break
                
            lineage.append(version_info)
            current_version = version_info["parent_version"]
            
        return lineage

def main():
    """Main function to demonstrate version management."""
    version_manager = DataVersionManager()
    
    try:
        # Example: Create a new version
        version_hash = version_manager.create_version(
            dataset_name="messages",
            file_path="data/processed/cleaned_messages.csv",
            version_notes="Initial cleaned dataset"
        )
        
        # List versions
        versions = version_manager.list_versions("messages")
        logger.info(f"Available versions: {json.dumps(versions, indent=2)}")
        
        # Get lineage
        lineage = version_manager.get_lineage("messages", version_hash)
        logger.info(f"Version lineage: {json.dumps(lineage, indent=2)}")
        
    except Exception as e:
        logger.error(f"Version management failed: {e}")
        raise

if __name__ == "__main__":
    main()
