import logging
import time
from typing import Optional, Any, Dict

from common.logging.setup import get_logger


class RequestLogger:
    """Context manager for request-specific logging with structured data"""

    def __init__(
        self,
        request_id: str,
        user_id: Optional[str] = None,
        operation: Optional[str] = None,
    ):
        """Initialize request logger with contextual information"""
        self.request_id: str = request_id
        self.user_id: Optional[str] = user_id
        self.operation: Optional[str] = operation
        self.logger: logging.Logger = get_logger("request")
        self.start_time: float = time.time()

    def __enter__(self) -> "RequestLogger":
        """Enter context manager"""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit context manager and log request completion"""
        duration: float = time.time() - self.start_time
        if exc_type:
            self.error(f"Request failed: {exc_val}", duration=duration)
        else:
            self.info("Request completed", duration=duration)

    def _log(self, level: str, message: str, **kwargs: Any) -> None:
        """Internal logging method with common extra fields"""
        extra_fields: Dict[str, Any] = {
            "request_id": self.request_id,
            "user_id": self.user_id,
            "operation": self.operation,
            **kwargs,
        }
        extra_fields = {k: v for k, v in extra_fields.items() if v is not None}
        getattr(self.logger, level)(message, extra={"extra_fields": extra_fields})

    def debug(self, message: str, **kwargs: Any) -> None:
        """Log debug message"""
        self._log("debug", message, **kwargs)

    def info(self, message: str, **kwargs: Any) -> None:
        """Log info message"""
        self._log("info", message, **kwargs)

    def warning(self, message: str, **kwargs: Any) -> None:
        """Log warning message"""
        self._log("warning", message, **kwargs)

    def error(self, message: str, **kwargs: Any) -> None:
        """Log error message"""
        self._log("error", message, **kwargs)

    def critical(self, message: str, **kwargs: Any) -> None:
        """Log critical message"""
        self._log("critical", message, **kwargs)
