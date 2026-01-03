"""Centralized logging configuration for the backend service."""
from __future__ import annotations

import os
from logging import config as logging_config

_DEFAULT_LOG_DIR = os.getenv("LOG_DIR", "/app/backend/logs")
_DEFAULT_MAX_BYTES = int(os.getenv("LOG_MAX_BYTES", 5 * 1024 * 1024))
_DEFAULT_BACKUP_COUNT = int(os.getenv("LOG_BACKUP_COUNT", 5))
_is_configured = False


def _build_handler(handler_name: str, filename: str, level: str) -> dict:
    """Helper to build a rotating file handler configuration."""
    return {
        "class": "logging.handlers.RotatingFileHandler",
        "level": level,
        "formatter": "detailed",
        "filename": filename,
        "maxBytes": _DEFAULT_MAX_BYTES,
        "backupCount": _DEFAULT_BACKUP_COUNT,
        "encoding": "utf-8",
    }


def configure_logging() -> None:
    """Configure application logging only once."""
    global _is_configured
    if _is_configured:
        return

    log_dir = os.getenv("LOG_DIR", _DEFAULT_LOG_DIR)
    os.makedirs(log_dir, exist_ok=True)

    base_level = os.getenv("LOG_LEVEL", "INFO").upper()

    handlers = {
        "console": {
            "class": "logging.StreamHandler",
            "level": base_level,
            "formatter": "colorless",
            "stream": "ext://sys.stdout",
        },
        "debug_file": _build_handler("debug_file", os.path.join(log_dir, "debug.log"), "DEBUG"),
        "info_file": _build_handler("info_file", os.path.join(log_dir, "info.log"), "INFO"),
        "error_file": _build_handler("error_file", os.path.join(log_dir, "error.log"), "ERROR"),
        "system_file": _build_handler("system_file", os.path.join(log_dir, "system.log"), "INFO"),
        "business_file": _build_handler("business_file", os.path.join(log_dir, "business.log"), "INFO"),
    }

    formatters = {
        "detailed": {
            "format": "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
        "colorless": {
            "format": "%(levelname)s | %(name)s | %(message)s",
        },
    }

    logging_dict = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": formatters,
        "handlers": handlers,
        "loggers": {
            "": {  # root logger
                "level": base_level,
                "handlers": ["console", "debug_file", "info_file", "error_file"],
            },
            "uvicorn": {
                "level": base_level,
                "handlers": ["console"],
                "propagate": False,
            },
            "uvicorn.error": {
                "level": base_level,
                "handlers": ["console"],
                "propagate": False,
            },
            "uvicorn.access": {
                "level": base_level,
                "handlers": ["console"],
                "propagate": False,
            },
            "system": {
                "level": "INFO",
                "handlers": ["system_file"],
                "propagate": True,
            },
            "business": {
                "level": "INFO",
                "handlers": ["business_file"],
                "propagate": True,
            },
        },
    }

    logging_config.dictConfig(logging_dict)
    _is_configured = True


def get_system_logger_name() -> str:
    return "system"


def get_business_logger_name() -> str:
    return "business"
