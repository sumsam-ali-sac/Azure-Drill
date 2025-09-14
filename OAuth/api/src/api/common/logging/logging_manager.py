import logging
from typing import Any
from src.api.config import get_settings
from src.api.common.logging.handlers import create_console_handler, create_file_handler
from src.api.common.logging.otel_setup import setup_otel

settings = get_settings()


class LoggingManager:
    """Centralized singleton manager for logging + tracing."""

    _instance: "LoggingManager" = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, config=None) -> None:
        self._settings = config or settings
        self._logger: logging.Logger | None = None
        self._tracer: Any = None

    def _suppress_noisy_loggers(self) -> None:
        for name in ("urllib3", "azure", "httpx", "opentelemetry"):
            logging.getLogger(name).setLevel(logging.WARNING)
        # Keep Uvicorn colored logs
        logging.getLogger("uvicorn.access").propagate = True
        logging.getLogger("uvicorn.error").propagate = True

    def setup(self) -> None:
        if self._logger is not None:
            return

        setup_otel(self._settings)

        root = logging.getLogger("my_app")
        level = getattr(
            logging,
            getattr(self._settings.logging, "LOG_LEVEL", "INFO").upper(),
            logging.INFO,
        )
        root.setLevel(level)

        # Clear previous handlers
        for h in root.handlers[:]:
            root.removeHandler(h)

        # Add handlers (OTel LoggingHandler added in otel_setup)
        root.addHandler(create_console_handler())
        fh = create_file_handler()
        if fh:
            root.addHandler(fh)

        self._logger = root
        self._suppress_noisy_loggers()

        # Get tracer after OTel setup
        from opentelemetry import trace

        self._tracer = trace.get_tracer("my_app")

    def get_logger(self, name: str) -> logging.Logger:
        if self._logger is None:
            self.setup()
        return logging.getLogger(name)

    def get_tracer(self) -> Any:
        if self._tracer is None:
            self.setup()
        return self._tracer


# ----------------- Global instance ----------------- #
_logging_manager = LoggingManager()
_logging_manager.setup()


def get_logger(name: str) -> logging.Logger:
    return _logging_manager.get_logger(name)


def get_tracer() -> Any:
    return _logging_manager.get_tracer()
