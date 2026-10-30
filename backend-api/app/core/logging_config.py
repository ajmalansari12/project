"""Centralized structured logging configuration for Sentinel-EDR."""

import logging
import sys
from typing import Optional

DEFAULT_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
DEFAULT_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging(
    log_level: str = "INFO",
    logger_name: Optional[str] = None,
) -> logging.Logger:
    """Configure centralized logging for Sentinel-EDR.

    Ensures that stream handlers are configured without duplicate registrations
    upon repeated initialization calls.

    Args:
        log_level: Minimum logging level ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL').
        logger_name: Specific logger to configure. If None, configures root logger.

    Returns:
        The configured Logger instance.
    """
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    target_logger = logging.getLogger(logger_name)
    target_logger.setLevel(numeric_level)

    # Avoid duplicate handlers if setup_logging is called multiple times
    has_stream_handler = any(
        isinstance(h, logging.StreamHandler) and h.stream == sys.stdout
        for h in target_logger.handlers
    )

    if not has_stream_handler:
        formatter = logging.Formatter(
            fmt=DEFAULT_LOG_FORMAT,
            datefmt=DEFAULT_DATE_FORMAT,
        )
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(formatter)
        stream_handler.setLevel(numeric_level)
        target_logger.addHandler(stream_handler)

    return target_logger
