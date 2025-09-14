"""
Custom exception classes for the chat application with HTTP status codes
"""

from typing import Optional, Dict, Any
from fastapi import status

from src.api.common.base.base_exception import BaseHTTPException


class AuthenticationError(BaseHTTPException):
    """Raised when authentication fails"""

    def __init__(
        self,
        message: str = "Authentication failed",
        headers: Optional[Dict[str, str]] = None,
        **kwargs
    ):
        # Add WWW-Authenticate header for 401 responses
        if headers is None:
            headers = {"WWW-Authenticate": "Bearer"}

        super().__init__(
            message=message,
            status_code=status.HTTP_401_UNAUTHORIZED,
            error_code="AUTH_ERROR",
            headers=headers,
            **kwargs
        )


class AuthorizationError(BaseHTTPException):
    """Raised when authorization fails"""

    def __init__(self, message: str = "Insufficient permissions", **kwargs):
        super().__init__(
            message=message,
            status_code=status.HTTP_403_FORBIDDEN,
            error_code="AUTHZ_ERROR",
            **kwargs
        )


class ValidationError(BaseHTTPException):
    """Raised when validation fails"""

    def __init__(self, message: str = "Validation failed", **kwargs):
        super().__init__(
            message=message,
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            error_code="VALIDATION_ERROR",
            **kwargs
        )


class NotFoundError(BaseHTTPException):
    """Raised when a resource is not found"""

    def __init__(self, message: str = "Resource not found", **kwargs):
        super().__init__(
            message=message,
            status_code=status.HTTP_404_NOT_FOUND,
            error_code="NOT_FOUND_ERROR",
            **kwargs
        )


class ConflictError(BaseHTTPException):
    """Raised when there's a conflict with existing data"""

    def __init__(self, message: str = "Resource conflict", **kwargs):
        super().__init__(
            message=message,
            status_code=status.HTTP_409_CONFLICT,
            error_code="CONFLICT_ERROR",
            **kwargs
        )


class FileUploadError(BaseHTTPException):
    """Raised when file upload fails"""

    def __init__(self, message: str = "File upload failed", **kwargs):
        super().__init__(
            message=message,
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            error_code="FILE_UPLOAD_ERROR",
            **kwargs
        )


class AzureServiceError(BaseHTTPException):
    """Raised when Azure service operations fail"""

    def __init__(self, message: str = "Azure service error", **kwargs):
        super().__init__(
            message=message,
            status_code=status.HTTP_502_BAD_GATEWAY,
            error_code="AZURE_SERVICE_ERROR",
            **kwargs
        )


class CacheError(BaseHTTPException):
    """Raised when cache operations fail"""

    def __init__(self, message: str = "Cache operation failed", **kwargs):
        super().__init__(
            message=message,
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            error_code="CACHE_ERROR",
            **kwargs
        )


class RateLimitError(BaseHTTPException):
    """Raised when rate limit is exceeded"""

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after: Optional[int] = None,
        **kwargs
    ):
        headers = {}
        if retry_after:
            headers["Retry-After"] = str(retry_after)

        super().__init__(
            message=message,
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            error_code="RATE_LIMIT_ERROR",
            headers=headers,
            **kwargs
        )


class DatabaseError(BaseHTTPException):
    """Raised when database operations fail"""

    def __init__(self, message: str = "Database operation failed", **kwargs):
        super().__init__(
            message=message,
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            error_code="DATABASE_ERROR",
            **kwargs
        )


class WebSocketError(BaseHTTPException):
    """Raised when WebSocket operations fail"""

    def __init__(self, message: str = "WebSocket operation failed", **kwargs):
        super().__init__(
            message=message,
            status_code=status.HTTP_400_BAD_REQUEST,
            error_code="WEBSOCKET_ERROR",
            **kwargs
        )


class ConfigurationError(BaseHTTPException):
    """Raised when configuration is invalid"""

    def __init__(self, message: str = "Configuration error", **kwargs):
        super().__init__(
            message=message,
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error_code="CONFIG_ERROR",
            **kwargs
        )


class BusinessLogicError(BaseHTTPException):
    """Raised when business logic validation fails"""

    def __init__(self, message: str = "Business logic error", **kwargs):
        super().__init__(
            message=message,
            status_code=status.HTTP_400_BAD_REQUEST,
            error_code="BUSINESS_LOGIC_ERROR",
            **kwargs
        )


class ExternalServiceError(BaseHTTPException):
    """Raised when external service calls fail"""

    def __init__(self, message: str = "External service error", **kwargs):
        super().__init__(
            message=message,
            status_code=status.HTTP_502_BAD_GATEWAY,
            error_code="EXTERNAL_SERVICE_ERROR",
            **kwargs
        )


class TimeoutError(BaseHTTPException):
    """Raised when operations timeout"""

    def __init__(self, message: str = "Operation timed out", **kwargs):
        super().__init__(
            message=message,
            status_code=status.HTTP_408_REQUEST_TIMEOUT,
            error_code="TIMEOUT_ERROR",
            **kwargs
        )
