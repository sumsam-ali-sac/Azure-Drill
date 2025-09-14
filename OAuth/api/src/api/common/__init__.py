"""
Common package initialization
"""

from src.api.common.exceptions import (
    AuthenticationError,
    ValidationError,
    FileUploadError,
    AzureServiceError,
    CacheError,
    RateLimitError
)
from src.api.common.logging import get_logger, setup_logging

__version__ = "1.0.0"
__all__ = [
    "AuthenticationError",
    "ValidationError",
    "FileUploadError",
    "AzureServiceError",
    "CacheError",
    "RateLimitError",
    "get_logger",
    "setup_logging"
]
