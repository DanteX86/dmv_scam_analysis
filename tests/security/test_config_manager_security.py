import os
from pathlib import Path

import pytest

from dmv_scam_analysis.utils.config_manager import ConfigManager, ConfigurationError


@pytest.mark.security
def test_config_manager_creates_defaults_and_loads(tmp_path, monkeypatch):
    cfg_dir = tmp_path / "config"
    cm = ConfigManager(config_dir=str(cfg_dir))

    # Defaults created
    assert (cfg_dir / "settings.yaml").exists()
    assert (cfg_dir / "environments" / "development.yaml").exists()
    # Loads and sets env
    assert cm.env is not None
    assert cm.env.name in ("development", "production")


@pytest.mark.security
def test_config_manager_missing_env_uses_defaults(tmp_path, monkeypatch):
    cfg_dir = tmp_path / "conf"
    # force ENV that doesn't exist
    monkeypatch.setenv("ENV", "nonexistent_env")
    cm = ConfigManager(config_dir=str(cfg_dir))
    # Should still have a valid environment object
    assert cm.env is not None
    assert cm.config.get("environment") is not None


@pytest.mark.security
def test_config_manager_load_yaml_errors(tmp_path):
    cfg_dir = tmp_path / "c"
    cm = ConfigManager(config_dir=str(cfg_dir))
    # Write invalid YAML
    bad_file = cfg_dir / "bad.yaml"
    bad_file.write_text(":: not yaml ::\n", encoding="utf-8")
    with pytest.raises(ConfigurationError):
        cm._load_yaml_file("bad.yaml")


@pytest.mark.security
def test_config_manager_merge_dicts():
    cm = ConfigManager(config_dir=str(Path.cwd() / "config"))
    base = {"a": 1, "b": {"x": 10, "y": 20}}
    override = {"b": {"y": 99, "z": 5}, "c": 3}
    merged = cm._merge_dicts(base, override)
    assert merged["a"] == 1
    assert merged["b"]["x"] == 10
    assert merged["b"]["y"] == 99
    assert merged["b"]["z"] == 5
    assert merged["c"] == 3
