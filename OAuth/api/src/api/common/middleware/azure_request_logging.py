from fastapi import Request
from src.api.common.logging.request_logger import RequestLogger
from src.api.common.middleware.request_logging import RequestLoggingMiddleware


class AzureRequestLoggingMiddleware(RequestLoggingMiddleware):
    """Azure-specific request logging with Application Insights integration"""

    def __init__(self, app):
        super().__init__(app)
        # sensitive_headers are already extended in app_settings.py and used by base class
        # No need to extend them again here.

    async def _log_request(self, req_logger: RequestLogger, request: Request):
        """Enhanced request logging with Azure context"""
        await super()._log_request(req_logger, request)  # Call base class method first
        azure_context = {
            "subscription_id": request.headers.get("x-ms-subscription-id"),
            "client_request_id": request.headers.get("x-ms-client-request-id"),
            "correlation_id": request.headers.get("x-ms-correlation-request-id"),
            "azure_region": request.headers.get("x-ms-azure-region")
        }
        # Filter out None values
        azure_context = {k: v for k,
                         v in azure_context.items() if v is not None}
        if azure_context:
            # Log Azure context as a separate info message
            req_logger.info("Azure context", **azure_context)
