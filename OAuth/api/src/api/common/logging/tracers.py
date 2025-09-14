from typing import Any
from opentelemetry import trace


class UnifiedTracer:
    """Unified tracer using OTel providers."""

    def __init__(self, service_name: str):
        self.service_name = service_name
        self._tracer = trace.get_tracer(service_name)

    def start_as_current_span(self, name: str, **kwargs: Any):
        return self._tracer.start_as_current_span(name, **kwargs)
