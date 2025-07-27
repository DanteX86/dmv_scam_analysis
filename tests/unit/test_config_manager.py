"""Unit tests for configuration manager."""
import os
import pytest
from dmv_scam_analysis.utils.config_manager import ConfigManager

@pytest.fixture
def config_manager():
    """Create a ConfigManager instance for testing."""
    return ConfigManager()

def test_load_config(config_manager):
    """Test loading configuration files."""
    config = config_manager.as_dict()
    assert config is not None
    assert "environment" in config
    assert "analysis" in config

def test_validate_config(config_manager):
    """Test configuration validation."""
    # Configuration is automatically validated on load
    config = config_manager.as_dict()
    assert config is not None
    # If we get here without exception, validation passed

def test_environment_override(config_manager):
    """Test environment variable overrides."""
    os.environ["ENV"] = "development"
    config_manager.reload()
    debug_value = config_manager.get("environment.debug")
    assert debug_value is True
    del os.environ["ENV"]

def test_config_reload(config_manager):
    """Test configuration reloading."""
    initial_config = config_manager.as_dict()
    config_manager.reload()
    reloaded_config = config_manager.as_dict()
    assert reloaded_config == initial_config

def test_invalid_config():
    """Test handling of invalid configuration."""
    # Test with a completely invalid directory path
    with pytest.raises(Exception):
        ConfigManager(config_dir="/root/nonexistent/path")
