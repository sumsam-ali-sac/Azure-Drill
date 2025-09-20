import logging
from typing import Any
from src.api.config import get_settings
from src.api.common.logging.handlers import create_console_handler, create_file_handler
from src.api.common.logging.otel_setup import setup_otel
from opentelemetry import trace

settings = get_settings()


# ----------------- Logger Manager ----------------- #
class LoggerManager:
    """Singleton for centralized logging setup."""

    _instance: "LoggerManager" = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init_once()
        return cls._instance

    def _init_once(self) -> None:
        if getattr(self, "_initialized", False):
            return
        self._initialized = True

        # Configure root logger
        root = logging.getLogger()
        level = getattr(logging, settings.logging.LOG_LEVEL.upper(), logging.INFO)
        root.setLevel(level)

        # Reset handlers
        root.handlers.clear()
        root.addHandler(create_console_handler())
        if fh := create_file_handler():
            root.addHandler(fh)

        # Suppress noisy libs
        for name in ("urllib3", "azure", "httpx", "opentelemetry"):
            logging.getLogger(name).setLevel(logging.WARNING)

        # Keep Uvicorn’s access/error logs
        logging.getLogger("uvicorn.access").propagate = True
        logging.getLogger("uvicorn.error").propagate = True

    def get_logger(self, name: str) -> logging.Logger:
        return logging.getLogger(f"uvicorn.{name}")


_logger_manager = LoggerManager()


def get_logger(name: str) -> logging.Logger:
    return _logger_manager.get_logger(name)
