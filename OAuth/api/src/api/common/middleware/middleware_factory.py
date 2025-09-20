from src.api.config import get_settings
from src.api.common.logging.logger_manager import get_logger
from src.api.common.middleware.request_logging import RequestLoggingMiddleware
from src.api.common.middleware.azure_request_logging import (
    AzureRequestLoggingMiddleware,
)

settings = get_settings()
_logger = get_logger(__name__)


def create_request_logging_middleware(**kwargs):
    """Return Azure or default RequestLoggingMiddleware based on settings."""
    if getattr(settings.azure.app_insights, "AZURE_APPINSIGHTS_CONNECTION_STRING", ""):
        _logger.info("Using AzureRequestLoggingMiddleware")
        return AzureRequestLoggingMiddleware
    _logger.info("Using RequestLoggingMiddleware")
    return RequestLoggingMiddleware
