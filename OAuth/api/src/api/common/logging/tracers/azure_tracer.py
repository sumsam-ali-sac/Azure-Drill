from typing import Any
from src.api.common.logging.tracers import BaseTracer

try:
    from opentelemetry import trace
    from opentelemetry.sdk.resources import SERVICE_NAME, Resource
    from azure.monitor.opentelemetry import configure_azure_monitor
    from opentelemetry.sdk.trace import TracerProvider

    AZURE_MONITOR_AVAILABLE = True
except ImportError:
    AZURE_MONITOR_AVAILABLE = False
    trace = None


class AzureTracer(BaseTracer):
    """Tracer for production using Azure Monitor."""

    def __init__(self, service_name: str, settings: Any):
        self.service_name = service_name
        if not AZURE_MONITOR_AVAILABLE or not getattr(
            settings.azure.app_insights, "AZURE_APPINSIGHTS_CONNECTION_STRING", ""
        ):
            from src.api.common.logging.tracers import NoOpTracer

            self._tracer = NoOpTracer(service_name)
            return

        # Idempotent: only configure once
        if trace.get_tracer_provider() is None or not isinstance(
            trace.get_tracer_provider(), TracerProvider
        ):
            resource = Resource.create({SERVICE_NAME: service_name})
            configure_azure_monitor(
                connection_string=settings.azure.app_insights.AZURE_APPINSIGHTS_CONNECTION_STRING,
                resource=resource,
            )

        self._tracer = trace.get_tracer(service_name)

    def start_as_current_span(self, name: str, **kwargs: Any):
        return self._tracer.start_as_current_span(name, **kwargs)
