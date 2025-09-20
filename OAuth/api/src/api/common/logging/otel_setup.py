import logging
from opentelemetry import trace
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.sdk._logs import LoggerProvider
from opentelemetry._logs import set_logger_provider
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor, ConsoleLogExporter
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from azure.monitor.opentelemetry import configure_azure_monitor
from opentelemetry.instrumentation.logging import LoggingInstrumentor
from src.api.config.settings import Settings


class OpenTelemetryConfig:
    """Configuration class for OpenTelemetry setup, including traces and logs."""

    def __init__(self, settings: Settings):
        self.env = settings.application.ENVIRONMENT or "development"
        self.service_name = "uvicorn." + __name__
        self.azure_cs = getattr(
            settings.azure.app_insights, "AZURE_APPINSIGHTS_CONNECTION_STRING", ""
        )
        self.jaeger_ep = getattr(settings.jaeger_otel, "JAEGER_ENDPOINT", "")
        self.resource = Resource.create({SERVICE_NAME: self.service_name})
        self.logger = logging.getLogger("uvicorn." + __name__)
        self.exporters = {
            "traces": "",
            "logs": "Console",
        }

    def _configure_azure(self):
        """Configure Azure Monitor for production, including traces and logs."""
        configure_azure_monitor(
            connection_string=self.azure_cs,
            resource=self.resource,
        )
        self.exporters.update(
            {
                "traces": "Azure",
                "logs": "Console, Azure",
            }
        )
        self.logger.info("Configured Azure Monitor for traces and logs")

    def _configure_traces(self):
        """Configure tracing with Jaeger or console exporter."""
        trace_provider = TracerProvider(resource=self.resource)
        exporter = (
            JaegerExporter(collector_endpoint=self.jaeger_ep)
            if self.jaeger_ep
            else ConsoleSpanExporter()
        )
        trace_provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(trace_provider)
        self.exporters["traces"] = "Jaeger" if self.jaeger_ep else "Console"
        self.logger.info(f"Trace exporter: {self.exporters['traces']}")

    def _configure_logs(self):
        """Configure logs to console (and Azure in production)."""
        log_provider = LoggerProvider(resource=self.resource)
        log_provider.add_log_record_processor(
            BatchLogRecordProcessor(ConsoleLogExporter())
        )
        set_logger_provider(log_provider)
        self.logger.info(f"Logs exporters: {self.exporters['logs']}")

    def _configure_metrics(self):
        """Configure metrics for the application."""
        self.exporters["metrics"] = "Console"
        self.logger.info(f"Metrics exporter: {self.exporters['metrics']}")

    def log_exporters(self):
        """Log the configured exporters for traces, logs, and metrics."""
        self.logger.info(
            f"OpenTelemetry exporters - Traces: {self.exporters['traces']}, "
            f"Logs: {self.exporters['logs']}, Metrics: {self.exporters.get('metrics','-')}"
        )


def setup_otel(settings: Settings):
    """Set up OpenTelemetry with Azure (prod) or Jaeger/console for traces and console for logs."""
    config = OpenTelemetryConfig(settings)
    try:
        if config.env == "production" and config.azure_cs:
            config._configure_azure()
            config._configure_logs()
        else:
            config._configure_traces()
            config._configure_logs()
            config._configure_metrics()

        # Instrument logging
        LoggingInstrumentor().instrument(set_logging_format=True)
        config.log_exporters()
        config.logger.info("OpenTelemetry setup completed successfully")

        return None  # TODO: return a MeterProvider later if needed
    except Exception as e:
        config.logger.error(f"OpenTelemetry setup failed: {e}", exc_info=True)
        raise
