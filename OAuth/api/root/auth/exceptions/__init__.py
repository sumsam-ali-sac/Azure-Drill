"""
Authentication exceptions module.
"""

from .auth_exceptions import (
    AuthServiceError,
    InvalidCredentialsError,
    UserNotFoundError,
    UserAlreadyExistsError,
    TokenExpiredError,
    InvalidTokenError,
    InvalidOTPError,
    ProviderError,
    ValidationError
)

__all__ = [
    "AuthServiceError",
    "InvalidCredentialsError", 
    "UserNotFoundError",
    "UserAlreadyExistsError",
    "TokenExpiredError",
    "InvalidTokenError",
    "InvalidOTPError",
    "ProviderError",
    "ValidationError"
]
