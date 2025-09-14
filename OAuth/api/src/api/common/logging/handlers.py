import logging
import sys
from typing import Optional
from src.api.common.logging.formatters import JSONFormatter
from src.api.common.logging.filters import TraceContextFilter
from src.api.config import get_settings

settings = get_settings()


def create_console_handler() -> logging.Handler:
    """Create and configure console handler"""
    handler = logging.StreamHandler(sys.stdout)
    if getattr(settings.logging, "LOG_FORMAT", "text").lower() == "json":
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - "
                "[trace_id=%(trace_id)s span_id=%(span_id)s] - %(message)s"
            )
        )
    handler.addFilter(TraceContextFilter())
    return handler


def create_file_handler() -> Optional[logging.Handler]:
    """Create and configure file handler"""
    path = getattr(settings.logging, "LOG_FILE", "")
    if not path:
        return None
    try:
        handler = logging.FileHandler(path)
        handler.setFormatter(JSONFormatter())
        handler.addFilter(TraceContextFilter())
        return handler
    except Exception as exc:
        logging.getLogger(__name__).error(f"Cannot create log file {path}: {exc}")
        return None
