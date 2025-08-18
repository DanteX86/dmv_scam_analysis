import os
from pathlib import Path

from dmv_scam_analysis.utils.config_manager import ConfigManager


def test_config_manager_roundtrip(tmp_path, monkeypatch):
    # Use a temp config dir
    cfg_dir = tmp_path / "config"
    cfg_dir.mkdir()
    # Use a non-existent env so no env overlay overrides our saved settings
    monkeypatch.setenv("ENV", "staging")

    cm = ConfigManager(config_dir=str(cfg_dir))

    # Change a couple of values
    cm.set("analysis.output_dir", str(tmp_path / "out"))
    cm.set("environment.debug", False)

    # Save and reload
    cm.save("settings.yaml")
    cm.reload()

    # Validate roundtrip
    assert cm.get("analysis.output_dir").endswith("out")
    assert cm.get("environment.debug") is False

    # Validate path helper
    p = cm.get_path("analysis.output_dir")
    assert isinstance(p, Path)
