from typing import Any
from src.api.common.logging.tracers import BaseTracer

try:
    from opentelemetry import trace
    from opentelemetry.sdk.resources import SERVICE_NAME, Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor

    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False
    trace = None


class ConsoleTracer(BaseTracer):
    """Tracer for development with ConsoleSpanExporter."""

    def __init__(self, service_name: str):
        self.service_name = service_name
        if not OTEL_AVAILABLE:
            from src.api.common.logging.tracers import NoOpTracer

            self._tracer = NoOpTracer(service_name)
            return

        # Idempotent: only set provider if none exists
        current_provider = trace.get_tracer_provider()
        if isinstance(current_provider, TracerProvider):
            resource = Resource.create({SERVICE_NAME: service_name})
            provider = TracerProvider(resource=resource)
            provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
            trace.set_tracer_provider(provider)

        self._tracer = trace.get_tracer(service_name)

    def start_as_current_span(self, name: str, **kwargs: Any):
        return self._tracer.start_as_current_span(name, **kwargs)
