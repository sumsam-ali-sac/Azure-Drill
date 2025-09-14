import logging
from opentelemetry import trace, metrics
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import (
    PeriodicExportingMetricReader,
    ConsoleMetricExporter,
)
from opentelemetry.sdk._logs import LoggerProvider
from opentelemetry._logs import set_logger_provider
from opentelemetry.sdk._logs.export import ConsoleLogExporter, BatchLogRecordProcessor
from opentelemetry.instrumentation.logging import LoggingInstrumentor
from opentelemetry.sdk.trace import SpanProcessor

try:
    from azure.monitor.opentelemetry import configure_azure_monitor

    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False


# CHANGED: Enhanced filtering for both http.response.start and http.response.body
class FilterASGISpans(SpanProcessor):
    """Custom processor to filter out redundant ASGI response spans"""

    def __init__(self, next_processors):
        self.next_processors = (
            next_processors if isinstance(next_processors, list) else [next_processors]
        )
        self.logger = logging.getLogger(__name__)

    def on_start(self, span, parent_context=None):
        for processor in self.next_processors:
            processor.on_start(span, parent_context)

    def on_end(self, span):
        # Filter out redundant ASGI spans
        if span.name.endswith("http send") and span.attributes.get(
            "asgi.event.type"
        ) in ["http.response.start", "http.response.body"]:
            self.logger.debug(f"Skipping redundant span: {span.name}")
            return  # Do not export
        for processor in self.next_processors:
            processor.on_end(span)

    def shutdown(self):
        for processor in self.next_processors:
            processor.shutdown()

    def force_flush(self, timeout_millis=30000):
        for processor in self.next_processors:
            processor.force_flush(timeout_millis)


def setup_otel(settings):
    """Centralized OTel setup, idempotent."""
    env = getattr(settings.application, "ENVIRONMENT", "development")
    service_name = getattr(settings.application, "APP_NAME", "default-python-service")
    resource = Resource.create({SERVICE_NAME: service_name})

    # Check if TracerProvider is a valid SDK provider
    current_tracer_provider = trace.get_tracer_provider()
    from opentelemetry.sdk.trace import TracerProvider as SDKTracerProvider

    if isinstance(current_tracer_provider, SDKTracerProvider):
        return

    try:
        if (
            env == "production"
            and AZURE_AVAILABLE
            and hasattr(settings, "azure")
            and hasattr(settings.azure, "app_insights")
            and getattr(
                settings.azure.app_insights, "AZURE_APPINSIGHTS_CONNECTION_STRING", ""
            )
        ):
            configure_azure_monitor(
                connection_string=settings.azure.app_insights.AZURE_APPINSIGHTS_CONNECTION_STRING,
                resource=resource,
            )
        else:
            # Configure TracerProvider
            trace_provider = TracerProvider(resource=resource)
            console_processor = BatchSpanProcessor(ConsoleSpanExporter())
            filtered_processor = FilterASGISpans(console_processor)
            trace_provider.add_span_processor(filtered_processor)
            trace.set_tracer_provider(trace_provider)

            # Configure MeterProvider
            metric_reader = PeriodicExportingMetricReader(ConsoleMetricExporter())
            meter_provider = MeterProvider(
                resource=resource, metric_readers=[metric_reader]
            )
            metrics.set_meter_provider(meter_provider)

            # Configure LoggerProvider
            log_provider = LoggerProvider(resource=resource)
            log_provider.add_log_record_processor(
                BatchLogRecordProcessor(ConsoleLogExporter())
            )
            set_logger_provider(log_provider)
    except Exception as e:
        logging.getLogger(__name__).error(
            f"Failed to configure OpenTelemetry: {e}", exc_info=True
        )
        raise

    # Instrument logging
    LoggingInstrumentor().instrument()
