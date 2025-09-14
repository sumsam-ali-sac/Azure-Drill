from src.api.common.middleware.request_logging import RequestLoggingMiddleware
from src.api.common.middleware.azure_request_logging import AzureRequestLoggingMiddleware
from src.api.config import get_settings

# Get the settings instance
settings = get_settings()


def create_request_logging_middleware(app, **kwargs):
    """Factory function to create appropriate request logging middleware based on settings."""
    # Check if Azure Application Insights connection string is provided as an indicator for Azure being enabled
    if settings.azure.app_insights.AZURE_APPINSIGHTS_CONNECTION_STRING:
        return AzureRequestLoggingMiddleware(app, **kwargs)
    else:
        return RequestLoggingMiddleware(app, **kwargs)
