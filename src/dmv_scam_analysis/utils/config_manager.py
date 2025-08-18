#!/usr/bin/env python3
"""
Configuration Management Module for SentinelAnalyzer

This module handles the loading, validation, and management of configurations
for the SentinelAnalyzer threat analysis platform.

Author: Cybersecurity Researcher
Version: 2.0
"""

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

# Try to import jsonschema for validation
try:
    import jsonschema

    JSONSCHEMA_AVAILABLE = True
except ImportError:
    JSONSCHEMA_AVAILABLE = False
    print("Warning: jsonschema not available. Configuration validation disabled.")

logger = logging.getLogger(__name__)


@dataclass
class Environment:
    """Environment configuration settings"""

    name: str = "development"
    debug: bool = True
    test_mode: bool = False
    timezone: str = "UTC"
    encoding: str = "utf-8"


class ConfigurationError(Exception):
    """Exception raised for configuration errors"""

    pass


class ConfigManager:
    """
    Manages configuration loading, validation, and access
    """

    def __init__(self, config_dir: str = "config"):
        """
        Initialize ConfigManager

        Args:
            config_dir: Path to configuration directory
        """
        self.config_dir = Path(config_dir)
        self.config: Dict[str, Any] = {}
        self.env: Optional[Environment] = None

        # Ensure config directory exists
        self.config_dir.mkdir(parents=True, exist_ok=True)

        # Create default configuration files if they don't exist
        self._create_default_configs()

        # Load configurations
        self._load_configs()

    def _create_default_configs(self) -> None:
        """Create default configuration files if they don't exist"""

        # Default main settings
        settings_file = self.config_dir / "settings.yaml"
        if not settings_file.exists():
            default_settings = {
                "sentinel_analyzer": {"version": "2.0", "name": "SentinelAnalyzer"},
                "environment": {
                    "name": "development",
                    "debug": True,
                    "test_mode": False,
                    "timezone": "UTC",
                    "encoding": "utf-8",
                },
                "analysis": {
                    "output_dir": "./analysis_output",
                    "nlp": {"enabled": True, "model_path": "./models/nlp/"},
                    "ml": {
                        "enabled": True,
                        "model_path": "./models/ml/",
                        "auto_train": False,
                    },
                    "behavioral": {"enabled": True, "time_window_hours": 24},
                },
                "logging": {
                    "level": "INFO",
                    "file": "./logs/sentinel.log",
                    "max_size": "10MB",
                    "backup_count": 5,
                },
            }

            with open(settings_file, "w") as f:
                yaml.dump(default_settings, f, default_flow_style=False, indent=2)

        # Default development environment
        env_dir = self.config_dir / "environments"
        env_dir.mkdir(exist_ok=True)

        dev_file = env_dir / "development.yaml"
        if not dev_file.exists():
            dev_config = {
                "environment": {
                    "name": "development",
                    "debug": True,
                    "test_mode": True,
                },
                "analysis": {"output_dir": "./dev_output"},
                "logging": {"level": "DEBUG"},
            }

            with open(dev_file, "w") as f:
                yaml.dump(dev_config, f, default_flow_style=False, indent=2)

        # Default production environment
        prod_file = env_dir / "production.yaml"
        if not prod_file.exists():
            prod_config = {
                "environment": {
                    "name": "production",
                    "debug": False,
                    "test_mode": False,
                },
                "analysis": {"output_dir": "/var/log/sentinel/analysis"},
                "logging": {"level": "INFO"},
            }

            with open(prod_file, "w") as f:
                yaml.dump(prod_config, f, default_flow_style=False, indent=2)

        # Default schema
        schema_file = self.config_dir / "schema.json"
        if not schema_file.exists() and JSONSCHEMA_AVAILABLE:
            schema = {
                "type": "object",
                "properties": {
                    "sentinel_analyzer": {
                        "type": "object",
                        "properties": {
                            "version": {"type": "string"},
                            "name": {"type": "string"},
                        },
                    },
                    "environment": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "debug": {"type": "boolean"},
                            "test_mode": {"type": "boolean"},
                            "timezone": {"type": "string"},
                            "encoding": {"type": "string"},
                        },
                        "required": ["name", "debug"],
                    },
                    "analysis": {
                        "type": "object",
                        "properties": {
                            "output_dir": {"type": "string"},
                            "nlp": {"type": "object"},
                            "ml": {"type": "object"},
                            "behavioral": {"type": "object"},
                        },
                    },
                    "logging": {
                        "type": "object",
                        "properties": {
                            "level": {"type": "string"},
                            "file": {"type": "string"},
                        },
                    },
                },
                "required": ["environment", "analysis"],
            }

            with open(schema_file, "w") as f:
                json.dump(schema, f, indent=2)

    def _load_configs(self) -> None:
        """Load configurations from YAML files"""
        try:
            # Load main settings
            main_config = self._load_yaml_file("settings.yaml")

            # Load environment-specific settings
            env_name = os.getenv("ENV", "development")
            env_config_path = f"environments/{env_name}.yaml"

            try:
                env_config = self._load_yaml_file(env_config_path)
            except ConfigurationError:
                logger.warning(
                    f"Environment config {env_config_path} not found, using defaults"
                )
                env_config = {}

            # Merge configurations
            self.config = self._merge_dicts(main_config, env_config)

            # Set up environment
            env_data = self.config.get("environment", {})
            self.env = Environment(**env_data)

            # Validate configuration
            self._validate_config()

        except Exception as e:
            raise ConfigurationError(f"Configuration loading error: {e}")

    def _load_yaml_file(self, filename: str) -> Dict[str, Any]:
        """
        Load a YAML configuration file

        Args:
            filename: Name of the YAML file to load

        Returns:
            Configuration data as a dictionary
        """
        filepath = self.config_dir / filename
        if not filepath.exists():
            raise ConfigurationError(f"Configuration file not found: {filepath}")

        try:
            with open(filepath, "r") as file:
                return yaml.safe_load(file) or {}
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Error parsing YAML file {filepath}: {e}")

    def _merge_dicts(self, base: Dict, override: Dict) -> Dict:
        """
        Merge two dictionaries recursively

        Args:
            base: Base dictionary
            override: Dictionary to override base values

        Returns:
            Merged dictionary
        """
        result = base.copy()

        for key, value in override.items():
            if (
                key in result
                and isinstance(result[key], dict)
                and isinstance(value, dict)
            ):
                result[key] = self._merge_dicts(result[key], value)
            else:
                result[key] = value

        return result

    def _validate_config(self) -> None:
        """Validate configuration against a JSON schema"""
        if not JSONSCHEMA_AVAILABLE:
            logger.warning("jsonschema not available, skipping validation")
            return

        schema_filepath = self.config_dir / "schema.json"
        if not schema_filepath.exists():
            logger.warning("Schema file not found, skipping validation")
            return

        try:
            with open(schema_filepath, "r") as schema_file:
                schema = json.load(schema_file)
                jsonschema.validate(instance=self.config, schema=schema)
            logger.info("Configuration validation successful")
        except jsonschema.exceptions.ValidationError as e:
            raise ConfigurationError(f"Configuration validation failed: {e}")
        except Exception as e:
            logger.warning(f"Schema validation error: {e}")

    def get(self, key: str, default: Any = None) -> Any:
        """
        Retrieve a value from the configuration

        Args:
            key: Configuration key (dot-delimited for nested keys)
            default: Default value if key isn't found

        Returns:
            Configuration value or default
        """
        keys = key.split(".")
        value = self.config

        try:
            for k in keys:
                if isinstance(value, dict) and k in value:
                    value = value[k]
                else:
                    return default
            return value
        except (KeyError, TypeError):
            return default

    def set(self, key: str, value: Any) -> None:
        """
        Set a configuration value

        Args:
            key: Configuration key (dot-delimited for nested keys)
            value: Value to set
        """
        keys = key.split(".")
        config = self.config

        # Navigate to the correct nested level
        for k in keys[:-1]:
            if k not in config or not isinstance(config[k], dict):
                config[k] = {}
            config = config[k]

        # Set the value
        config[keys[-1]] = value

    def save(self, filename: str = "settings.yaml") -> None:
        """
        Save the current configuration back to file

        Args:
            filename: Name of file to save to
        """
        filepath = self.config_dir / filename
        try:
            with open(filepath, "w") as config_file:
                yaml.dump(self.config, config_file, default_flow_style=False, indent=2)
            logger.info(f"Configuration saved to {filepath}")
        except Exception as e:
            raise ConfigurationError(f"Error saving configuration: {e}")

    def reload(self) -> None:
        """Reload configuration from files"""
        self._load_configs()
        logger.info("Configuration reloaded")

    def validate_required(self, keys: List[str]) -> None:
        """
        Validate that required configuration keys are present

        Args:
            keys: List of required configuration keys

        Raises:
            ConfigurationError: If any required keys are missing
        """
        missing = []
        for key in keys:
            if self.get(key) is None:
                missing.append(key)

        if missing:
            raise ConfigurationError(
                f"Missing required configuration keys: {', '.join(missing)}"
            )

    def as_dict(self) -> Dict[str, Any]:
        """
        Get complete configuration as dictionary

        Returns:
            Configuration dictionary
        """
        return self.config.copy()

    def get_path(self, key: str) -> Path:
        """
        Get configuration value as Path object

        Args:
            key: Configuration key for path

        Returns:
            Path object
        """
        value = self.get(key)
        if not value:
            raise ConfigurationError(f"Path not found in configuration: {key}")
        return Path(value)

    def is_development(self) -> bool:
        """Check if running in development environment"""
        return bool(self.env and self.env.name == "development")

    def is_production(self) -> bool:
        """Check if running in production environment"""
        return bool(self.env and self.env.name == "production")

    def get_analysis_config(self) -> Dict[str, Any]:
        """Get analysis-specific configuration"""
        value = self.get("analysis", {})
        return dict(value) if isinstance(value, dict) else {}

    def get_logging_config(self) -> Dict[str, Any]:
        """Get logging-specific configuration"""
        value = self.get("logging", {})
        return dict(value) if isinstance(value, dict) else {}

    def update_from_env(self, prefix: str = "SENTINEL_") -> None:
        """
        Update configuration from environment variables

        Args:
            prefix: Environment variable prefix to look for
        """
        for key, value in os.environ.items():
            if key.startswith(prefix):
                config_key = key[len(prefix) :].lower().replace("_", ".")
                self.set(config_key, value)
                logger.info(f"Updated config from env: {config_key} = {value}")


# Global configuration instance
_config_instance: Optional[ConfigManager] = None


def get_config() -> ConfigManager:
    """
    Get singleton configuration manager instance

    Returns:
        ConfigManager instance
    """
    global _config_instance
    if _config_instance is None:
        _config_instance = ConfigManager()
    return _config_instance


def main() -> int:
    """Main function to demonstrate configuration management"""
    try:
        # Initialize configuration
        config = get_config()

        print("🔧 SentinelAnalyzer Configuration Manager")
        print("=" * 50)

        # Print current configuration
        print("Current Configuration:")
        print(json.dumps(config.as_dict(), indent=2))

        # Print environment info
        if config.env is not None:
            print(f"\nEnvironment: {config.env.name}")
            print(f"Debug Mode: {config.env.debug}")
            print(f"Test Mode: {config.env.test_mode}")
        else:
            print("\nEnvironment: <unset>")

        # Test configuration access
        print(f"\nOutput Directory: {config.get('analysis.output_dir')}")
        print(f"NLP Enabled: {config.get('analysis.nlp.enabled')}")
        print(f"ML Enabled: {config.get('analysis.ml.enabled')}")

        print("\n✓ Configuration validation successful!")

    except ConfigurationError as e:
        print(f"❌ Configuration error: {e}")
        return 1
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
