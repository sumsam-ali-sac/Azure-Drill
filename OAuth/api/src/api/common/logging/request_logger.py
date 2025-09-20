import logging
import time
import json
from typing import Optional, Any, Dict
from opentelemetry import trace
from src.api.config.settings import get_settings
from src.api.common.logging.logger_manager import get_logger

settings = get_settings()


class RequestLogger:
    """Context manager for request-specific logging with structured JSON output"""

    def __init__(
        self,
        request_id: str,
        user_id: Optional[str] = None,
        operation: Optional[str] = None,
    ):
        self.request_id: str = request_id
        self.user_id: Optional[str] = user_id
        self.operation: Optional[str] = operation
        self.logger: logging.Logger = get_logger(settings.application.APP_NAME)
        self.start_time: float = time.time()
        self.tracer = trace.get_tracer(__name__)
        self.span = None

    def __enter__(self) -> "RequestLogger":
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

    def _log(self, level: str, message: str, **kwargs: Any) -> None:
        """Log as structured JSON with all request/response fields"""
        log_entry: Dict[str, Any] = {
            "message": message,
            "level": level.upper(),
            "request_id": self.request_id,
            "user_id": self.user_id,
            "operation": self.operation,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
            **{k: v for k, v in kwargs.items() if v is not None},
        }
        self.logger.log(getattr(logging, level.upper()), json.dumps(log_entry))

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
