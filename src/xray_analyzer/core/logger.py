"""Logging configuration with structlog."""

import logging
import sys

import structlog

from xray_analyzer.core.config import settings

_PROJECT_LOGGER_NAME = "xray_analyzer"


def setup_logging() -> None:
    """Configure structured logging: stderr warnings + JSON file.

    Console output goes to stderr at WARNING+ so it doesn't mix with Rich's
    stdout panels/tables. Full DEBUG/INFO stream goes to the log file.
    """
    log_level = getattr(logging, settings.log_level.upper(), logging.INFO)

    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="%H:%M:%S"),
    ]

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Console handler — WARNING+ only, goes to stderr so Rich stdout stays clean
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.WARNING)
    console_formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.dev.ConsoleRenderer(
                colors=True,
                exception_formatter=structlog.dev.plain_traceback,
            ),
        ],
        foreign_pre_chain=shared_processors,
    )
    console_handler.setFormatter(console_formatter)

    # File handler — full log at configured level, JSON for machine parsing
    file_handler = logging.FileHandler(settings.log_file, encoding="utf-8")
    file_handler.setLevel(log_level)
    file_formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.dict_tracebacks,
            structlog.processors.JSONRenderer(),
        ],
        foreign_pre_chain=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
        ],
    )
    file_handler.setFormatter(file_formatter)

    # Use project-specific logger instead of root logger
    # This avoids interfering with third-party libraries
    project_logger = logging.getLogger(_PROJECT_LOGGER_NAME)
    project_logger.handlers.clear()
    project_logger.addHandler(console_handler)
    project_logger.addHandler(file_handler)
    project_logger.setLevel(log_level)
    project_logger.propagate = False

    # Silence third-party noisy loggers
    for name in ("aiohttp", "asyncio"):
        logging.getLogger(name).setLevel(logging.WARNING)


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Get a configured logger instance scoped to the project logger."""
    full_name = f"{_PROJECT_LOGGER_NAME}.{name}" if name else _PROJECT_LOGGER_NAME
    return structlog.get_logger(full_name)
