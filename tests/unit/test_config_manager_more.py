import os
import pytest

from dmv_scam_analysis.utils.config_manager import ConfigManager, ConfigurationError


def test_validate_required_and_get_path_missing(tmp_path, monkeypatch):
    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir()
    monkeypatch.setenv("ENV", "staging")
    cm = ConfigManager(config_dir=str(cfg_dir))

    # Missing required key should raise
    with pytest.raises(ConfigurationError):
        cm.validate_required(["does.not.exist"])

    # get_path missing should raise
    with pytest.raises(ConfigurationError):
        cm.get_path("not.there")


def test_load_yaml_file_parsing_error(tmp_path, monkeypatch):
    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir()
    monkeypatch.setenv("ENV", "staging")
    cm = ConfigManager(config_dir=str(cfg_dir))

    # Write invalid YAML
    bad = cfg_dir / "bad.yaml"
    bad.write_text("a: [1, 2", encoding="utf-8")

    with pytest.raises(ConfigurationError):
        cm._load_yaml_file("bad.yaml")

