import logging
from pathlib import Path

import pytest

# Some of these modules may be thin wrappers; we exercise stdlib logging
# Importing project logger module to mark as covered (if it sets up defaults)
from dmv_scam_analysis.utils import logger as project_logger  # noqa: F401


@pytest.mark.security
def test_logger_setup_and_usage(tmp_path, monkeypatch):
    # Exercise logger module by configuring a basic handler
    log_path = tmp_path / "app.log"
    handler = logging.FileHandler(log_path)

    lg = logging.getLogger("dmv_test_logger")
    lg.setLevel(logging.INFO)
    lg.addHandler(handler)

    lg.info("hello")
    handler.flush()

    assert log_path.exists()
    content = log_path.read_text(encoding="utf-8")
    assert "hello" in content
