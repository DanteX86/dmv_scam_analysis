import logging
import os
from pathlib import Path

import yaml

from dmv_scam_analysis.utils import logger as logmod


def test_log_manager_setup_fallback(tmp_path, monkeypatch):
    # Point to a non-existent logging config to trigger fallback
    cfg = tmp_path / "no_such_config.yaml"
    lm = logmod.LogManager()
    lm.setup(str(cfg))

    # App and error loggers should have handlers after fallback
    app_lg = logging.getLogger("app")
    err_lg = logging.getLogger("error")
    assert app_lg.handlers
    assert err_lg.handlers

    # Filters should be present (ContextFilter) on these loggers
    assert any(isinstance(f, logmod.ContextFilter) for f in app_lg.filters)
    assert any(isinstance(f, logmod.ContextFilter) for f in err_lg.filters)


def test_log_manager_rotate_and_archive(tmp_path, monkeypatch):
    # Use project-relative 'logs' dir because implementation scans Path("logs")
    cwd_logs = Path("logs")
    try:
        cwd_logs.mkdir(exist_ok=True)
        # Create a dummy rolled file expected by archive_logs
        rolled = cwd_logs / "app.log.1"
        rolled.write_text("old data")

        lm = logmod.LogManager()
        archive_dir = tmp_path / "archive"
        lm.archive_logs(str(archive_dir))

        archived = list(archive_dir.glob("app.log_*"))
        assert archived, "Expected archived files in archive dir"
    finally:
        # Cleanup created files
        for p in cwd_logs.glob("app.log.*"):
            try:
                p.unlink()
            except Exception:
                pass
        # Do not remove logs dir if it may be used by other tests


def test_load_logging_config_happy_path(tmp_path, monkeypatch):
    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir()
    out_dir = tmp_path / "out_logs"
    out_dir.mkdir()

    # Minimal dictConfig YAML with a file handler
    cfg = {
        "version": 1,
        "formatters": {"simple": {"format": "%(levelname)s:%(message)s"}},
        "handlers": {
            "file": {
                "class": "logging.FileHandler",
                "level": "INFO",
                "formatter": "simple",
                "filename": str(out_dir / "test.log"),
            }
        },
        "loggers": {
            "app": {
                "handlers": ["file"],
                "level": "INFO",
                "propagate": False,
            }
        },
        "root": {"handlers": ["file"], "level": "WARNING"},
    }

    cfg_path = cfg_dir / "logging.yaml"
    with open(cfg_path, "w") as f:
        yaml.safe_dump(cfg, f)

    # Should load without error and create directories if needed
    logmod.load_logging_config(str(cfg_path))

    # Emitting a log should create the file
    lg = logging.getLogger("app")
    lg.info("configured")
    assert (out_dir / "test.log").exists()
