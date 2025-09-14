import logging
import sys
from typing import Optional

# Import the centralized settings object from its correct nested path
from src.api.config import get_settings

# Assuming src.api.common.logging.formatters defines JSONFormatter
# (Ensure this file exists and contains your JSONFormatter class)
from src.api.common.logging.formatters import JSONFormatter

# Get the settings instance
settings = get_settings()

# Attempt to import OpenTelemetry and Azure Monitor components
try:
    from opentelemetry import trace
    from opentelemetry.sdk.resources import SERVICE_NAME, Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor, BatchSpanProcessor
    from azure.monitor.opentelemetry import configure_azure_monitor
    from azure.monitor.opentelemetry.exporter import AzureMonitorTraceExporter
    OTEL_AVAILABLE = True
    AZURE_MONITOR_AVAILABLE = True
except ImportError as e:
    OTEL_AVAILABLE = False
    AZURE_MONITOR_AVAILABLE = False
    print(
        f"Warning: OpenTelemetry or Azure Monitor SDK not installed. Tracing will be disabled. Error: {e}", file=sys.stderr)

# Global tracer instance, initialized to a NoOpTracer if OpenTelemetry is not available.
# This ensures TRACER is always a valid object, avoiding None checks throughout the application.
TRACER: trace.Tracer = trace.get_tracer("noop")


def _setup_otel_tracing() -> trace.Tracer:
    """
    Configures OpenTelemetry tracing, integrating with Azure Application Insights if enabled.
    Returns the configured OpenTelemetry Tracer instance.
    """
    global TRACER
    if not OTEL_AVAILABLE:
        print("OpenTelemetry not available. Tracing will be disabled.", file=sys.stderr)
        TRACER = trace.get_tracer("noop")  # Explicitly set to no-op tracer
        return TRACER

    # Access settings via the nested structure (e.g., settings.application.APP_NAME)
    service_name = settings.application.APP_NAME or "default-python-service"
    resource = Resource.create({SERVICE_NAME: service_name})

    if AZURE_MONITOR_AVAILABLE and settings.azure.app_insights.AZURE_APPINSIGHTS_CONNECTION_STRING:
        try:
            # configure_azure_monitor sets up logging, metrics, and tracing for Azure Monitor.
            # It also sets the global tracer provider internally.
            configure_azure_monitor(
                connection_string=settings.azure.app_insights.AZURE_APPINSIGHTS_CONNECTION_STRING,
                resource=resource,
                # Optionally disable specific components if not needed
                # disable_logging=False,
                # disable_metrics=False,
                # disable_tracing=False,
            )
            TRACER = trace.get_tracer(service_name)
            print("Azure Monitor configured successfully for tracing.")
        except Exception as e:
            print(
                f"Error configuring Azure Monitor for tracing: {e}", file=sys.stderr)
            # Fallback to no-op on configuration error
            TRACER = trace.get_tracer("noop")
    else:
        # Manual OpenTelemetry configuration if Azure Monitor is not used or connection string is missing.
        provider = TracerProvider(resource=resource)
        # Use ConsoleSpanExporter for development for immediate visibility.
        # For production without Azure Monitor, consider OTLPTraceExporter with BatchSpanProcessor.
        if settings.application.ENVIRONMENT == "development":
            span_processor = SimpleSpanProcessor(ConsoleSpanExporter())
            print("OpenTelemetry configured with ConsoleSpanExporter for development.")
        else:
            # If not development and no Azure Monitor, no specific exporter is configured by default.
            # You might add a default OTLP exporter here if desired for non-Azure production environments.
            # Example: span_processor = BatchSpanProcessor(OTLPTraceExporter())
            print("OpenTelemetry configured without a specific exporter (no Azure connection string and not development).")
            span_processor = None  # No span processor means no spans are exported
        if span_processor:
            provider.add_span_processor(span_processor)
        trace.set_tracer_provider(provider)
        TRACER = trace.get_tracer(service_name)
        print("OpenTelemetry configured manually.")
    return TRACER


def setup_logging() -> None:
    """
    Configures the logging system with console and optional file handlers.
    Sets up JSON formatting and integrates with OpenTelemetry tracing.
    This function is idempotent and can be called multiple times safely.
    """
    # Initialize tracing first, so loggers can potentially include trace context.
    _setup_otel_tracing()

    root_logger = logging.getLogger()
    # Ensure log level is valid, default to INFO if not.
    log_level = getattr(
        logging, settings.logging.LOG_LEVEL.upper(), logging.INFO)
    root_logger.setLevel(log_level)

    # Clear existing handlers to prevent duplicate logs if setup_logging is called multiple times.
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Setup console handler for standard output.
    console_handler = logging.StreamHandler(sys.stdout)
    if settings.logging.LOG_FORMAT == "json":
        console_handler.setFormatter(JSONFormatter())
    else:
        console_handler.setFormatter(
            logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        )
    root_logger.addHandler(console_handler)

    # Setup file handler if a log file path is specified in settings.
    if settings.logging.LOG_FILE:
        try:
            file_handler = logging.FileHandler(settings.logging.LOG_FILE)
            # Always use JSON format for file logs for easier parsing by log aggregators.
            file_handler.setFormatter(JSONFormatter())
            root_logger.addHandler(file_handler)
        except Exception as e:
            root_logger.error(
                f"Failed to set up file logger at '{settings.logging.LOG_FILE}': {e}")

    # Suppress noisy third-party loggers to keep application logs clean and focused.
    for logger_name in ("urllib3", "azure", "httpx", "uvicorn", "asyncio"):
        logging.getLogger(logger_name).setLevel(logging.WARNING)

    # Prevent duplicate access and error logs from uvicorn by disabling propagation.
    logging.getLogger("uvicorn.access").propagate = False
    logging.getLogger("uvicorn.error").propagate = False


def get_logger(name: str) -> logging.Logger:
    """
    Retrieves a configured logger instance for a given name.
    """
    return logging.getLogger(name)


def get_tracer() -> trace.Tracer:
    """
    Retrieves the global OpenTelemetry tracer instance.
    This tracer will be a NoOpTracer if OpenTelemetry was not successfully configured.
    """
    return TRACER
