from .base_tracer import BaseTracer
from .noop_tracer import NoOpTracer
from .console_tracer import ConsoleTracer
from .azure_tracer import AzureTracer


def get_tracer(service_name: str, config=None):
    """Factory function to get appropriate tracer based on environment."""
    from src.api.config import get_settings

    settings = config or get_settings()
    environment = getattr(settings.application, "ENVIRONMENT", "development")

    if environment == "development":
        return ConsoleTracer(service_name)
    elif environment == "production" and getattr(
        settings.azure.app_insights, "AZURE_APPINSIGHTS_CONNECTION_STRING", ""
    ):
        return AzureTracer(service_name, settings)
    return NoOpTracer(service_name)


__all__ = ["BaseTracer", "NoOpTracer", "ConsoleTracer", "AzureTracer", "get_tracer"]
