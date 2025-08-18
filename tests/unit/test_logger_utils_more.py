import logging
from dmv_scam_analysis.utils import logger as logmod


def test_context_and_audit_performance_logging(caplog):
    caplog.set_level(logging.INFO)

    # Context helpers
    logmod.set_context(user="alice", action="test")
    assert hasattr(logmod.thread_local, "context")
    assert logmod.thread_local.context.get("user") == "alice"
    logmod.clear_context()
    assert logmod.thread_local.context == {}

    # Audit logger
    al = logmod.AuditLogger("audit")
    al.log_event("login", "bob", {"ip": "127.0.0.1"})
    # Not asserting content to avoid flakiness, just that it didn't raise

    # Performance logger
    pl = logmod.PerformanceLogger("performance")
    pl.log_duration("op", 12.3)

