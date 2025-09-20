from opentelemetry import trace
from typing import Any
from src.api.common.logging.otel_setup import setup_otel
from src.api.config import get_settings

settings = get_settings()


class TracerManager:
    """Singleton for OpenTelemetry tracer setup."""

    _instance: "TracerManager" = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init_once()
        return cls._instance

    def _init_once(self) -> None:
        if getattr(self, "_initialized", False):
            return
        self._initialized = True

        # Setup OTel once
        setup_otel(settings)
        self._tracer = trace.get_tracer("uvicorn.app")

    def get_tracer(self, name: str = __name__) -> Any:
        return trace.get_tracer(f"uvicorn.{name}")


_tracer_manager = TracerManager()


def get_tracer(name: str = __name__) -> Any:
    return _tracer_manager.get_tracer(name)
