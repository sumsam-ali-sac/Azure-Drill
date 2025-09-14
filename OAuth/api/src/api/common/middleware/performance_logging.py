import time
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request
from src.api.common.logging import get_logger
from src.api.config import settings

logger = get_logger(__name__)


class PerformanceLoggingMiddleware(BaseHTTPMiddleware):
    """Performance-focused logging middleware"""

    def __init__(self, app):
        super().__init__(app)
        self.slow_request_threshold = settings.performance_monitoring.SLOW_REQUEST_THRESHOLD

    async def dispatch(self, request: Request, call_next):
        """Log performance metrics"""
        start_time = time.time()
        response = await call_next(request)
        duration = time.time() - start_time
        if duration > self.slow_request_threshold:
            logger.warning(
                f"Slow request detected: {request.method} {request.url.path}",
                extra={
                    "duration": duration,
                    "threshold": self.slow_request_threshold,
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": response.status_code,
                    "request_id": request.state.request_id if hasattr(request.state, 'request_id') else "N/A"
                }
            )
        return response
