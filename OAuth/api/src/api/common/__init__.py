"""
Common package initialization
"""

from src.api.common.exceptions import (
    AuthenticationError,
    ValidationError,
    FileUploadError,
    AzureServiceError,
    CacheError,
    RateLimitError,
)

__version__ = "1.0.0"
__all__ = [
    "AuthenticationError",
    "ValidationError",
    "FileUploadError",
    "AzureServiceError",
    "CacheError",
    "RateLimitError",
]
