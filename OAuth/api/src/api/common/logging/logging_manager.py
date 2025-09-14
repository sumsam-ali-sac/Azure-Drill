import logging
from typing import Any
from src.api.config import get_settings
from src.api.common.logging.handlers import create_console_handler, create_file_handler
from src.api.common.logging.tracers import NoOpTracer, ConsoleTracer, AzureTracer

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

    def _setup_tracing(self) -> Any:
        if self._tracer is not None:
            return self._tracer

        env = getattr(self._settings.application, "ENVIRONMENT", "development")
        service_name = getattr(
            self._settings.application, "APP_NAME", "default-python-service"
        )

        if env == "development":
            self._tracer = ConsoleTracer(service_name)
        elif env == "production" and getattr(
            self._settings.azure.app_insights, "AZURE_APPINSIGHTS_CONNECTION_STRING", ""
        ):
            self._tracer = AzureTracer(service_name, self._settings)
        else:
            self._tracer = NoOpTracer(service_name)

        return self._tracer

    def _suppress_noisy_loggers(self) -> None:
        for name in ("urllib3", "azure", "httpx"):
            logging.getLogger(name).setLevel(logging.WARNING)
        # Keep Uvicorn colored logs
        logging.getLogger("uvicorn.access").propagate = True
        logging.getLogger("uvicorn.error").propagate = True

    def setup(self) -> None:
        if self._logger is not None:
            return

        # Init tracer first
        self._setup_tracing()

        root = logging.getLogger("my_app")  # use app-specific logger
        level = getattr(
            logging,
            getattr(self._settings.logging, "LOG_LEVEL", "INFO").upper(),
            logging.INFO,
        )
        root.setLevel(level)

        # Clear previous handlers
        for h in root.handlers[:]:
            root.removeHandler(h)

        # Add handlers
        root.addHandler(create_console_handler())
        fh = create_file_handler()
        if fh:
            root.addHandler(fh)

        self._logger = root
        self._suppress_noisy_loggers()

    def get_logger(self, name: str) -> logging.Logger:
        if self._logger is None:
            self.setup()
        return logging.getLogger(name)

    def get_tracer(self) -> Any:
        if self._tracer is None:
            self._setup_tracing()
        return self._tracer


# ----------------- Global instance ----------------- #
_logging_manager = LoggingManager()
_logging_manager.setup()


def get_logger(name: str) -> logging.Logger:
    return _logging_manager.get_logger(name)


def get_tracer() -> Any:
    return _logging_manager.get_tracer()
