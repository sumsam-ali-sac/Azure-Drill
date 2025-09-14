from typing import Any
from src.api.common.logging.tracers import BaseTracer


class NoOpTracer(BaseTracer):
    """No-op tracer when OpenTelemetry is unavailable."""

    def __init__(self, service_name: str):
        self.service_name = service_name

    def start_as_current_span(self, name: str, **kwargs: Any):
        class _Ctx:
            def __enter__(self):
                return None

            def __exit__(self, exc_type, exc, tb):
                return False

        return _Ctx()
