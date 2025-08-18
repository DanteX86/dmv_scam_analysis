#!/usr/bin/env python3
"""
Logging utility module for DMV scam analysis project.
Provides logging setup and custom logging functionality.
"""

import logging
import logging.config
import logging.handlers
import yaml
from pathlib import Path
import time
import sys
from functools import wraps
from typing import Optional, Callable, Any, Dict, Union
from datetime import datetime
import threading
from types import TracebackType

# Thread-local storage for context variables
thread_local = threading.local()


def setup_logging(
    name: str, level: int = logging.INFO, config_path: str = "config/logging_config.yaml"
) -> logging.Logger:
    """
    Set up logging configuration from a YAML file or use basic configuration.

    Args:
        name: Name of the logger
        level: Logging level
        config_path: Path to logging configuration file

    Returns:
        Configured logger
    """
    try:
        # Try to load configuration from file
        load_logging_config(config_path)
        logger = logging.getLogger(name)
        logger.setLevel(level)
        return logger
    except FileNotFoundError:
        # Fall back to basic configuration
        return setup_logger(name, level=level)


def load_logging_config(config_path: Union[str, Path] = "config/logging_config.yaml") -> None:
    """
    Load logging configuration from YAML file.

    Args:
        config_path: Path to logging configuration file
    """
    path_obj = Path(config_path)

    if path_obj.exists():
        with open(path_obj, "r") as f:
            config = yaml.safe_load(f)

        # Ensure log directories exist
        for handler in config.get("handlers", {}).values():
            if "filename" in handler:
                log_file = Path(handler["filename"])
                log_file.parent.mkdir(parents=True, exist_ok=True)

        logging.config.dictConfig(config)
    else:
        raise FileNotFoundError(f"Logging configuration file not found: {config_path}")


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance with the specified name.

    Args:
        name: Name of the logger

    Returns:
        Logger instance
    """
    return logging.getLogger(name)


def setup_logger(name: str, log_dir: str = "./logs", level: int = logging.INFO) -> logging.Logger:
    """
    Set up a logger with basic configuration.

    Args:
        name: Name of the logger
        log_dir: Directory for log files
        level: Logging level

    Returns:
        Configured logger instance
    """
    # Create log directory if it doesn't exist
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Avoid adding multiple handlers if logger already exists
    if not logger.handlers:
        # Create file handler
        log_file = log_path / f"{name.lower()}.log"
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)

        # Create console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)

        # Create formatter
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        # Add handlers to logger
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    return logger


class ContextFilter(logging.Filter):
    """Custom filter to add context to log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        # Add thread-local context to record
        for key, value in getattr(thread_local, "context", {}).items():
            setattr(record, key, value)
        return True


def set_context(**kwargs: Any) -> None:
    """Set context variables for logging.

    Args:
        **kwargs: Key-value pairs to add to context
    """
    if not hasattr(thread_local, "context"):
        thread_local.context = {}
    thread_local.context.update(kwargs)


def clear_context() -> None:
    """Clear all context variables."""
    if hasattr(thread_local, "context"):
        thread_local.context.clear()


class AuditLogger:
    """Logger class for audit events."""

    def __init__(self, logger_name: str = "audit"):
        self.logger = logging.getLogger(logger_name)

    def log_event(self, action: str, user: str, details: Dict[str, Any]) -> None:
        """
        Log an audit event.

        Args:
            action: Action being performed
            user: User performing the action
            details: Additional event details
        """
        set_context(user=user, action=action)
        try:
            self.logger.info(f"{action} - {details}")
        finally:
            clear_context()


class PerformanceLogger:
    """Logger class for performance metrics."""

    def __init__(self, logger_name: str = "performance"):
        self.logger = logging.getLogger(logger_name)

    def log_duration(self, operation: str, duration_ms: float) -> None:
        """
        Log operation duration.

        Args:
            operation: Operation being measured
            duration_ms: Duration in milliseconds
        """
        set_context(duration=duration_ms)
        try:
            self.logger.info(f"{operation}")
        finally:
            clear_context()


def log_execution_time(logger: Optional[logging.Logger] = None) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Decorator to log function execution time.

    Args:
        logger: Logger to use (defaults to performance logger)

    Returns:
        Decorator function
    """
    perf_logger = PerformanceLogger()

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                duration_ms = (time.time() - start_time) * 1000
                perf_logger.log_duration(
                    operation=f"{func.__module__}.{func.__name__}", duration_ms=duration_ms
                )

        return wrapper

    return decorator


def setup_exception_logging(logger: Optional[logging.Logger] = None) -> None:
    """
    Set up global exception handler for logging unhandled exceptions.

    Args:
        logger: Logger to use (defaults to error logger)
    """
    error_logger = logger or logging.getLogger("error")

    def handle_exception(
        exc_type: type[BaseException],
        exc_value: BaseException,
        exc_traceback: Optional[TracebackType],
    ) -> None:
        if issubclass(exc_type, KeyboardInterrupt):
            # Call default handler for Ctrl+C
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return

        error_logger.error(
            "Uncaught exception:",
            exc_info=(exc_type, exc_value, exc_traceback),
        )

    # Set the exception handler
    sys.excepthook = handle_exception


class LogManager:
    """Central manager for logging functionality."""

    def __init__(self) -> None:
        self.app_logger = logging.getLogger("app")
        self.error_logger = logging.getLogger("error")
        self.audit_logger = AuditLogger()
        self.performance_logger = PerformanceLogger()

    def setup(self, config_path: str = "config/logging_config.yaml") -> None:
        """
        Set up logging infrastructure.

        Args:
            config_path: Path to logging configuration file
        """
        # Load configuration
        try:
            load_logging_config(config_path)
        except FileNotFoundError:
            # Setup basic logging if config file not found
            setup_logger("app")
            setup_logger("error")
            setup_logger("audit")
            setup_logger("performance")

        # Add context filter to all loggers
        context_filter = ContextFilter()
        for logger in [self.app_logger, self.error_logger]:
            logger.addFilter(context_filter)

        # Set up exception handling
        setup_exception_logging(self.error_logger)

    def rotate_logs(self) -> None:
        """Rotate all log files."""
        for handler in logging.root.handlers:
            if isinstance(
                handler,
                (logging.handlers.RotatingFileHandler, logging.handlers.TimedRotatingFileHandler),
            ):
                handler.doRollover()

    def archive_logs(self, archive_dir: str) -> None:
        """
        Archive old log files.

        Args:
            archive_dir: Directory to store archived logs
        """
        archive_path = Path(archive_dir)
        archive_path.mkdir(parents=True, exist_ok=True)

        # Create timestamp for archive
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Move old log files to archive
        log_dir = Path("logs")
        for log_file in log_dir.rglob("*.log.*"):
            archive_name = f"{log_file.stem}_{timestamp}{log_file.suffix}"
            archive_file = archive_path / archive_name
            log_file.rename(archive_file)


def main() -> None:
    """Main function to demonstrate logging setup."""
    # Initialize logging
    log_manager = LogManager()
    log_manager.setup()

    # Get logger instances
    app_logger = logging.getLogger("app")
    error_logger = logging.getLogger("error")
    audit_logger = AuditLogger()
    perf_logger = PerformanceLogger()

    # Example usage
    try:
        # Application logging
        app_logger.info("Application started")

        # Audit logging
        audit_logger.log_event(action="user_login", user="test_user", details={"ip": "127.0.0.1"})

        # Performance logging
        set_context(operation="data_processing")
        start_time = time.time()
        # Simulate work
        time.sleep(1)
        duration_ms = (time.time() - start_time) * 1000
        perf_logger.log_duration("data_processing", duration_ms)
        clear_context()

        # Error logging
        raise ValueError("Example error")

    except Exception:
        error_logger.exception("An error occurred")

    finally:
        app_logger.info("Application finished")


if __name__ == "__main__":
    main()
