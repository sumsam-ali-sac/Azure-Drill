from fastapi import Request
from src.api.common.middleware.request_logging import RequestLoggingMiddleware
from src.api.common.logging.request_logger import RequestLogger
from src.api.config import get_settings
from src.api.common.logging.logging_manager import get_logger
from opentelemetry import trace

settings = get_settings()
_logger = get_logger("my_app")


class AzureRequestLoggingMiddleware(RequestLoggingMiddleware):
    """Request logging with Azure Application Insights context."""

    def __init__(self, app, log_level="INFO"):
        super().__init__(app, log_level)
        conn_str = getattr(
            settings.azure.app_insights, "AZURE_APPINSIGHTS_CONNECTION_STRING", None
        )
        if not conn_str:
            _logger.warning("Azure AppInsights connection string not configured")
        else:
            _logger.info("AzureRequestLoggingMiddleware initialized")

    async def _log_request(self, req_logger: RequestLogger, request: Request):
        await super()._log_request(req_logger, request)
        azure_context = {
            "subscription_id": request.headers.get("x-ms-subscription-id"),
            "client_request_id": request.headers.get("x-ms-client-request-id"),
            "correlation_id": request.headers.get("x-ms-correlation-request-id"),
            "azure_region": request.headers.get("x-ms-azure-region"),
        }
        azure_context = {k: v for k, v in azure_context.items() if v}
        if azure_context:
            req_logger.info("Azure context", **azure_context)
            span = trace.get_current_span()
            for k, v in azure_context.items():
                span.set_attribute(f"azure.{k}", v)
