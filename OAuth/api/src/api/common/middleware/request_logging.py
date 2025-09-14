import time
import uuid
import json
import traceback
from typing import Optional, Dict, Any
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from src.api.common.logging.request_logger import RequestLogger
# Import the centralized settings object from its correct nested path
from src.api.config import get_settings

# Get the settings instance
settings = get_settings()


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Enhanced request logging middleware.
    Logs request and response details, handles sensitive data masking,
    and integrates with RequestLogger for contextual logging.
    """

    def __init__(self, app):
        super().__init__(app)
        # Pull settings directly from the global settings object
        self.log_request_body = settings.request_response_logging.LOG_REQUEST_BODY
        self.log_response_body = settings.request_response_logging.LOG_RESPONSE_BODY
        self.max_body_size = settings.request_response_logging.MAX_BODY_SIZE
        self.skip_paths = settings.request_response_logging.SKIP_PATHS
        self.sensitive_headers = [
            h.lower() for h in settings.request_response_logging.SENSITIVE_HEADERS]
        self.sensitive_json_fields = [
            f.lower() for f in settings.request_response_logging.SENSITIVE_JSON_FIELDS]

    async def dispatch(self, request: Request, call_next):
        """Log request and response details"""
        path = request.url.path
        if any(path.startswith(skip_path) for skip_path in self.skip_paths):
            return await call_next(request)

        # Use X-Request-ID header if provided, otherwise generate a new one
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id  # Store for access in endpoints

        user_id = None
        # Assuming user info might be set by an auth middleware earlier
        if hasattr(request.state, "user") and request.state.user:
            user_id = request.state.user.get("user_id")

        start_time = time.time()
        operation_name = f"{request.method} {path}"

        # Use RequestLogger as a context manager to create a span and add context to logs
        with RequestLogger(request_id, user_id, operation_name) as req_logger:
            try:
                await self._log_request(req_logger, request)
                response = await call_next(request)
                duration = time.time() - start_time
                await self._log_response(req_logger, request, response, duration)
                response.headers["X-Request-ID"] = request_id
                return response
            except Exception as e:
                duration = time.time() - start_time
                req_logger.error(
                    "Request failed",
                    exception_type=type(e).__name__,
                    exception_msg=str(e),
                    stack_trace=traceback.format_exc(),
                    duration=duration
                )
                raise  # Re-raise the exception to be handled by FastAPI's exception handlers

    async def _log_request(self, req_logger: RequestLogger, request: Request):
        """Log request details"""
        client_ip = self._get_client_ip(request)
        user_agent = request.headers.get("user-agent", "")
        request_data = {
            "method": request.method,
            "url": str(request.url),
            "path": request.url.path,
            "query_params": dict(request.query_params),
            "client_ip": client_ip,
            "user_agent": user_agent,
            "headers": self._sanitize_headers(dict(request.headers))
        }
        if self.log_request_body and request.method in ["POST", "PUT", "PATCH"]:
            # Read body once and store it for later use if needed by endpoint
            # This requires careful handling as request.body() consumes the stream
            # For simplicity, we'll just read it for logging here.
            # For full re-usability, consider https://fastapi.tiangolo.com/tutorial/body-from-form/#re-using-the-body
            body = await request.body()
            if body:
                request_data["body"] = self._process_body(body)
        req_logger.info("Request started", **request_data)

    async def _log_response(
        self,
        req_logger: RequestLogger,
        request: Request,
        response: Response,
        duration: float
    ):
        """Log response details"""
        response_data = {
            "status_code": response.status_code,
            "duration_ms": round(duration * 1000, 2),
            "response_size": len(response.body) if hasattr(response, 'body') else 0,
            "headers": self._sanitize_headers(dict(response.headers))
        }
        if self.log_response_body and hasattr(response, 'body') and len(response.body) <= self.max_body_size:
            try:
                # Ensure response body is read before it's sent
                # This might require cloning the response if you need to read it
                # without interfering with FastAPI's normal response handling.
                # For simple logging, accessing response.body might be sufficient
                # if the response is already buffered.
                response_data["body"] = response.body.decode('utf-8')
            except UnicodeDecodeError:
                response_data["body"] = "<binary data>"
            except Exception as e:
                response_data["body"] = f"<error decoding body: {e}>"

        if response.status_code >= 500:
            req_logger.error(
                "Request completed with server error", **response_data)
        elif response.status_code >= 400:
            req_logger.warning(
                "Request completed with client error", **response_data)
        else:
            req_logger.info("Request completed successfully", **response_data)

    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address, considering various proxy headers."""
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        # Specific to Azure App Service/Functions
        client_ip = request.headers.get("X-Azure-ClientIP")
        if client_ip:
            return client_ip
        return request.client.host if request.client else "unknown"

    def _sanitize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Sanitize headers by masking sensitive values."""
        sanitized = {}
        for key, value in headers.items():
            if key.lower() in self.sensitive_headers:
                if len(value) > 8:
                    sanitized[key] = value[:4] + "****" + value[-4:]
                else:
                    sanitized[key] = "****"
            else:
                sanitized[key] = value
        return sanitized

    def _process_body(self, body: bytes) -> Optional[str]:
        """Process request body, attempting JSON parsing and sanitization."""
        if len(body) > self.max_body_size:
            # Truncate and indicate truncation
            body = body[:self.max_body_size] + b"..."
        try:
            json_body = json.loads(body)
            sanitized_body = self._sanitize_json_body(json_body)
            return json.dumps(sanitized_body)
        except json.JSONDecodeError:
            # Decode as string, replace errors
            return body.decode('utf-8', errors='replace')

    def _sanitize_json_body(self, body: Any) -> Any:
        """Sanitize sensitive fields in JSON body recursively."""
        if isinstance(body, dict):
            sanitized = {}
            for key, value in body.items():
                if any(sensitive_field in key.lower() for sensitive_field in self.sensitive_json_fields):
                    sanitized[key] = "****"
                elif isinstance(value, (dict, list)):
                    sanitized[key] = self._sanitize_json_body(value)
                else:
                    sanitized[key] = value
            return sanitized
        elif isinstance(body, list):
            return [self._sanitize_json_body(item) for item in body]
        else:
            return body
