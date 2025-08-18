import json
import os
from pathlib import Path

import pytest

from dmv_scam_analysis.utils.config_manager import ConfigManager, ConfigurationError


@pytest.mark.security
def test_config_manager_get_set_and_paths(tmp_path, monkeypatch):
    cfg_dir = tmp_path / "cfg"
    cm = ConfigManager(config_dir=str(cfg_dir))

    # get/set nested
    cm.set("analysis.nlp.enabled", False)
    assert cm.get("analysis.nlp.enabled") is False

    # get with default
    assert cm.get("nonexistent.key", default=123) == 123

    # get_path existing
    out_dir = cm.get_path("analysis.output_dir")
    assert isinstance(out_dir, Path)

    # update_from_env respects prefix
    monkeypatch.setenv("SENTINEL_LOGGING_LEVEL", "WARNING")
    cm.update_from_env()
    assert cm.get("logging.level") == "WARNING"

    # save and reload
    cm.save()
    before = cm.as_dict()
    cm.reload()
    after = cm.as_dict()
    assert isinstance(after, dict) and after


@pytest.mark.security
def test_config_manager_validation_warnings_and_errors(tmp_path, monkeypatch):
    cfg_dir = tmp_path / "cf"
    cm = ConfigManager(config_dir=str(cfg_dir))

    # If jsonschema missing, _validate_config should warn and return without error
    # Force missing schema file
    (cfg_dir / "schema.json").unlink(missing_ok=True)
    cm._validate_config()  # should not raise

    # Corrupt schema file should trigger a warning path, not crash
    (cfg_dir / "schema.json").write_text("{ not: json }", encoding="utf-8")
    cm._validate_config()  # should not raise
