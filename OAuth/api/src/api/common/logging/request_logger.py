import logging
import time
from typing import Optional, Any, Dict
from opentelemetry import trace
from src.api.common.logging.logging_manager import get_logger


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
        self.logger: logging.Logger = get_logger("my_app")
        self.start_time: float = time.time()
        self.tracer = trace.get_tracer(__name__)
        self.span = None

    def __enter__(self) -> "RequestLogger":
        # Reuse existing current span instead of creating a new one
        self.span = trace.get_current_span()
        if self.span and self.span.is_recording():
            self.span.set_attribute("request_id", self.request_id)
            if self.user_id:
                self.span.set_attribute("user_id", self.user_id)
        else:
            self.logger.warning(
                "No valid span found for request_id=%s", self.request_id
            )
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        duration: float = time.time() - self.start_time
        if exc_type:
            if self.span and self.span.is_recording():
                self.span.record_exception(exc_val)
                self.span.set_status(trace.StatusCode.ERROR)
            self.error(f"Request failed: {exc_val}", duration=duration)
        else:
            if self.span and self.span.is_recording():
                self.span.set_status(trace.StatusCode.OK)
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
        self._log("debug", message, **kwargs)

    def info(self, message: str, **kwargs: Any) -> None:
        self._log("info", message, **kwargs)

    def warning(self, message: str, **kwargs: Any) -> None:
        self._log("warning", message, **kwargs)

    def error(self, message: str, **kwargs: Any) -> None:
        self._log("error", message, **kwargs)

    def critical(self, message: str, **kwargs: Any) -> None:
        self._log("critical", message, **kwargs)
