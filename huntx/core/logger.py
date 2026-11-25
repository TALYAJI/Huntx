"""HUNTX logging setup."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

_ROOT_LOGGER_NAME = "huntx"


def setup_logger(
    session_log_path: Path,
    log_level: int | str = logging.DEBUG,
) -> logging.Logger:
    """Configure the root HUNTX logger.

    Attaches a file handler (DEBUG+) and a console handler (WARNING+).

    Args:
        session_log_path: Absolute path to the log file for this session.
        log_level: Minimum level for the file handler (default: DEBUG).

    Returns:
        The configured root ``huntx`` logger.
    """
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    logger = logging.getLogger(_ROOT_LOGGER_NAME)
    logger.setLevel(log_level)

    # Avoid duplicate handlers on repeated calls
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
        handler.close()

    # File handler — captures everything at or above log_level
    session_log_path.parent.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(session_log_path, encoding="utf-8")
    file_handler.setLevel(log_level)
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    # Console handler — only warnings and above
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(fmt)
    logger.addHandler(console_handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """Return a named child logger under the root ``huntx`` logger.

    Args:
        name: Sub-name, e.g. ``"core.session"`` or ``"engines.android"``.

    Returns:
        A :class:`logging.Logger` whose full name is ``huntx.<name>``.
    """
    return logging.getLogger(f"{_ROOT_LOGGER_NAME}.{name.removeprefix(_ROOT_LOGGER_NAME + '.')}")


class LogContext:
    """Helper that logs structured start/end/fail events for a named operation.

    Usage::

        ctx = LogContext()
        ctx.start("APK parsing")
        try:
            ...
            ctx.end("APK parsing", success=True)
        except Exception as exc:
            ctx.fail("APK parsing", exc)
    """

    def __init__(self, logger: Optional[logging.Logger] = None) -> None:
        self._log = logger or get_logger("log_context")

    def start(self, operation: str) -> None:
        """Log the beginning of *operation*."""
        self._log.info("START  %s", operation)

    def end(self, operation: str, success: bool = True) -> None:
        """Log the completion of *operation*.

        Args:
            operation: The operation name.
            success: ``True`` if completed successfully, ``False`` for soft failure.
        """
        if success:
            self._log.info("END    %s [OK]", operation)
        else:
            self._log.warning("END    %s [FAILED]", operation)

    def fail(self, operation: str, error: Exception) -> None:
        """Log an unexpected error during *operation*.

        Args:
            operation: The operation name.
            error: The exception that caused the failure.
        """
        self._log.error("FAIL   %s — %s: %s", operation, type(error).__name__, error)
