import logging
import os
import types

import pytest

from dmv_scam_analysis.utils import logger as logmod


def test_setup_logger_creates_handlers(tmp_path, monkeypatch):
    # Ensure a clean logger
    name = "unit_test_logger"
    lg = logging.getLogger(name)
    for h in list(lg.handlers):
        lg.removeHandler(h)

    test_log_dir = tmp_path / "logs"
    res_logger = logmod.setup_logger(
        name, log_dir=str(test_log_dir), level=logging.DEBUG
    )
    assert isinstance(res_logger, logging.Logger)
    assert res_logger.level == logging.DEBUG
    # Should have file and console handlers
    assert any(isinstance(h, logging.FileHandler) for h in res_logger.handlers)
    assert any(isinstance(h, logging.StreamHandler) for h in res_logger.handlers)


def test_log_execution_time_decorator_records_duration(monkeypatch):
    perf_names = []
    durations = []

    class DummyPerf(logmod.PerformanceLogger):
        def log_duration(self, operation: str, duration_ms: float) -> None:
            perf_names.append(operation)
            durations.append(duration_ms)

    # Patch PerformanceLogger used inside decorator
    monkeypatch.setattr(logmod, "PerformanceLogger", DummyPerf)

    @logmod.log_execution_time()
    def sample_func(x, y):
        return x + y

    result = sample_func(2, 3)
    assert result == 5
    assert len(durations) == 1
    assert durations[0] >= 0.0
    assert perf_names[0].endswith("sample_func")


def test_setup_exception_logging(monkeypatch):
    test_logger = logging.getLogger("error")
    captured = {"called": False, "msg": None}

    def fake_error(msg, *args, **kwargs):
        captured["called"] = True
        captured["msg"] = msg

    monkeypatch.setattr(test_logger, "error", fake_error)
    logmod.setup_exception_logging(test_logger)

    class DummyExc(Exception):
        pass

    # Simulate excepthook call
    sys_hook = getattr(__import__("sys"), "excepthook")
    sys_hook(DummyExc, DummyExc("boom"), None)

    assert captured["called"] is True
    assert "Uncaught exception" in captured["msg"]
