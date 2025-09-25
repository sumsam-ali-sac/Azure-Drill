"""
Custom exceptions for the authentication module.
Provides specific error types with appropriate HTTP status codes.
"""

from typing import Optional, Dict, Any
from fastapi import HTTPException
from root.authcommon.constants import (
    HTTP_400_BAD_REQUEST,
    HTTP_401_UNAUTHORIZED,
    HTTP_403_FORBIDDEN,
    HTTP_404_NOT_FOUND,
    HTTP_429_TOO_MANY_REQUESTS,
    HTTP_500_INTERNAL_SERVER_ERROR,
    ERROR_INVALID_CREDENTIALS,
    ERROR_OTP_INVALID,
    ERROR_TOKEN_EXPIRED,
    ERROR_TOKEN_INVALID,
    ERROR_INSUFFICIENT_PERMISSIONS,
    ERROR_RATE_LIMIT_EXCEEDED,
    ERROR_USER_NOT_FOUND,
    ERROR_EMAIL_ALREADY_EXISTS,
    ERROR_WEAK_PASSWORD,
    ERROR_INVALID_EMAIL,
    ERROR_OAUTH_ERROR,
    ERROR_CSRF_MISMATCH,
)


class AuthBaseException(HTTPException):
    """Base exception class for authentication errors."""

    def __init__(
        self,
        status_code: int,
        detail: str,
        headers: Optional[Dict[str, Any]] = None,
        error_code: Optional[str] = None,
    ):
        super().__init__(status_code=status_code, detail=detail, headers=headers)
        self.error_code = error_code


class InvalidCredentialsError(AuthBaseException):
    """Raised when user provides invalid login credentials."""

    def __init__(self, detail: str = ERROR_INVALID_CREDENTIALS):
        super().__init__(
            status_code=HTTP_401_UNAUTHORIZED,
            detail=detail,
            error_code="INVALID_CREDENTIALS",
        )


class OTPInvalidError(AuthBaseException):
    """Raised when OTP code is invalid or expired."""

    def __init__(self, detail: str = ERROR_OTP_INVALID):
        super().__init__(
            status_code=HTTP_401_UNAUTHORIZED, detail=detail, error_code="OTP_INVALID"
        )


class TokenExpiredError(AuthBaseException):
    """Raised when JWT token has expired."""

    def __init__(self, detail: str = ERROR_TOKEN_EXPIRED):
        super().__init__(
            status_code=HTTP_401_UNAUTHORIZED, detail=detail, error_code="TOKEN_EXPIRED"
        )


class InvalidTokenError(AuthBaseException):
    """Raised when JWT token is invalid or malformed."""

    def __init__(self, detail: str = ERROR_TOKEN_INVALID):
        super().__init__(
            status_code=HTTP_401_UNAUTHORIZED, detail=detail, error_code="TOKEN_INVALID"
        )


class InsufficientPermissionsError(AuthBaseException):
    """Raised when user lacks required permissions."""

    def __init__(self, detail: str = ERROR_INSUFFICIENT_PERMISSIONS):
        super().__init__(
            status_code=HTTP_403_FORBIDDEN,
            detail=detail,
            error_code="INSUFFICIENT_PERMISSIONS",
        )


class RateLimitExceededError(AuthBaseException):
    """Raised when rate limit is exceeded."""

    def __init__(self, detail: str = ERROR_RATE_LIMIT_EXCEEDED):
        super().__init__(
            status_code=HTTP_429_TOO_MANY_REQUESTS,
            detail=detail,
            error_code="RATE_LIMIT_EXCEEDED",
        )


class UserNotFoundError(AuthBaseException):
    """Raised when user is not found."""

    def __init__(self, detail: str = ERROR_USER_NOT_FOUND):
        super().__init__(
            status_code=HTTP_404_NOT_FOUND, detail=detail, error_code="USER_NOT_FOUND"
        )


class EmailAlreadyExistsError(AuthBaseException):
    """Raised when email already exists during registration."""

    def __init__(self, detail: str = ERROR_EMAIL_ALREADY_EXISTS):
        super().__init__(
            status_code=HTTP_400_BAD_REQUEST,
            detail=detail,
            error_code="EMAIL_ALREADY_EXISTS",
        )


class WeakPasswordError(AuthBaseException):
    """Raised when password doesn't meet security requirements."""

    def __init__(self, detail: str = ERROR_WEAK_PASSWORD):
        super().__init__(
            status_code=HTTP_400_BAD_REQUEST, detail=detail, error_code="WEAK_PASSWORD"
        )


class InvalidEmailError(AuthBaseException):
    """Raised when email format is invalid."""

    def __init__(self, detail: str = ERROR_INVALID_EMAIL):
        super().__init__(
            status_code=HTTP_400_BAD_REQUEST, detail=detail, error_code="INVALID_EMAIL"
        )


class OAuthError(AuthBaseException):
    """Raised when OAuth authentication fails."""

    def __init__(self, detail: str = ERROR_OAUTH_ERROR, provider: Optional[str] = None):
        if provider:
            detail = f"{provider.title()} OAuth error: {detail}"
        super().__init__(
            status_code=HTTP_400_BAD_REQUEST, detail=detail, error_code="OAUTH_ERROR"
        )


class CSRFError(AuthBaseException):
    """Raised when CSRF token validation fails."""

    def __init__(self, detail: str = ERROR_CSRF_MISMATCH):
        super().__init__(
            status_code=HTTP_400_BAD_REQUEST, detail=detail, error_code="CSRF_ERROR"
        )


class AccountLockedError(AuthBaseException):
    """Raised when user account is locked due to failed attempts."""

    def __init__(
        self, detail: str = "Account is locked due to too many failed attempts"
    ):
        super().__init__(
            status_code=HTTP_403_FORBIDDEN, detail=detail, error_code="ACCOUNT_LOCKED"
        )


class AuthConfigurationError(AuthBaseException):
    """Raised when authentication configuration is invalid."""

    def __init__(self, detail: str = "Authentication configuration error"):
        super().__init__(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            detail=detail,
            error_code="CONFIG_ERROR",
        )


class EmailSendError(AuthBaseException):
    """Raised when email sending fails."""

    def __init__(self, detail: str = "Failed to send email"):
        super().__init__(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            detail=detail,
            error_code="EMAIL_SEND_ERROR",
        )


class CacheError(AuthBaseException):
    """Raised when cache operations fail."""

    def __init__(self, detail: str = "Cache operation failed"):
        super().__init__(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            detail=detail,
            error_code="CACHE_ERROR",
        )


# Exception mapping for easier handling
EXCEPTION_MAP = {
    "invalid_credentials": InvalidCredentialsError,
    "otp_invalid": OTPInvalidError,
    "token_expired": TokenExpiredError,
    "token_invalid": InvalidTokenError,
    "insufficient_permissions": InsufficientPermissionsError,
    "rate_limit_exceeded": RateLimitExceededError,
    "user_not_found": UserNotFoundError,
    "email_already_exists": EmailAlreadyExistsError,
    "weak_password": WeakPasswordError,
    "invalid_email": InvalidEmailError,
    "oauth_error": OAuthError,
    "csrf_error": CSRFError,
    "account_locked": AccountLockedError,
    "config_error": AuthConfigurationError,
    "email_send_error": EmailSendError,
    "cache_error": CacheError,
}


def get_exception_by_code(
    error_code: str, detail: Optional[str] = None
) -> AuthBaseException:
    """Get exception instance by error code."""
    exception_class = EXCEPTION_MAP.get(error_code, AuthBaseException)
    if detail:
        return exception_class(detail)
    return exception_class()
