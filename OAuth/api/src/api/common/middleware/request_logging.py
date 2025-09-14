import time
import uuid
import json
import traceback
from typing import Any, Optional, Dict
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from src.api.common.logging.request_logger import RequestLogger
from src.api.config import get_settings
from src.api.common.logging.logging_manager import get_logger
from opentelemetry import trace

settings = get_settings()
_logger = get_logger(settings.application.APP_NAME)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Logs all requests and responses safely with OTel spans."""

    def __init__(self, app, log_level="INFO"):
        super().__init__(app)
        self.log_request_body = settings.request_response_logging.LOG_REQUEST_BODY
        self.log_response_body = settings.request_response_logging.LOG_RESPONSE_BODY
        self.max_body_size = settings.request_response_logging.MAX_BODY_SIZE
        self.skip_paths = settings.request_response_logging.SKIP_PATHS
        self.sensitive_headers = [
            h.lower() for h in settings.request_response_logging.SENSITIVE_HEADERS
        ]
        self.sensitive_json_fields = [
            f.lower() for f in settings.request_response_logging.SENSITIVE_JSON_FIELDS
        ]
        self.log_level = log_level

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if any(path.startswith(skip) for skip in self.skip_paths):
            return await call_next(request)

        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id
        user_id = getattr(
            getattr(request.state, "user", {}), "get", lambda k, d=None: None
        )("user_id")

        req_logger = RequestLogger(request_id, user_id, f"{request.method} {path}")
        request.state.logger = req_logger

        start_time = time.time()
        with req_logger:  # This starts the span
            try:
                await self._log_request(req_logger, request)
                response = await call_next(request)
                duration = time.time() - start_time
                await self._log_response(req_logger, request, response, duration)
                if response is not None:
                    response.headers["X-Request-ID"] = request_id
                return response
            except Exception as e:
                duration = time.time() - start_time
                req_logger.error(
                    "Request failed",
                    exception_type=type(e).__name__,
                    exception_msg=str(e),
                    stack_trace=traceback.format_exc(),
                    duration=duration,
                )
                raise

    async def _log_request(self, req_logger: RequestLogger, request: Request):
        try:
            client_ip = self._get_client_ip(request)
            request_data = {
                "method": request.method,
                "url": str(request.url),
                "path": request.url.path,
                "query_params": dict(request.query_params),
                "client_ip": client_ip,
                "user_agent": request.headers.get("user-agent", ""),
                "headers": self._sanitize_headers(dict(request.headers)),
            }
            if self.log_request_body and request.method in ["POST", "PUT", "PATCH"]:
                body = await request.body()
                if body:
                    request_data["body"] = self._process_body(body)
            req_logger.info("Request started", **request_data)
            # Add attributes to span
            span = trace.get_current_span()
            if span:
                for k, v in request_data.items():
                    if isinstance(v, (str, int, float, bool)):
                        span.set_attribute(f"request.{k}", v)
        except Exception as e:
            _logger.error(f"Failed to log request: {e}", exc_info=True)

    async def _log_response(
        self,
        req_logger: RequestLogger,
        request: Request,
        response: Optional[Response],
        duration: float,
    ):
        try:
            headers = {}
            if response and hasattr(response, "headers"):
                headers = {k: v for k, v in response.headers.items()}

            response_body = None
            response_size = 0

            if response and hasattr(response, "body"):
                response_body = response.body or b""
                response_size = len(response_body)
                if self.log_response_body and response_size <= self.max_body_size:
                    try:
                        response_body = response_body.decode("utf-8")
                    except UnicodeDecodeError:
                        response_body = "<binary data>"
                    except Exception as e:
                        response_body = f"<error decoding body: {e}>"
                else:
                    response_body = None

            response_data = {
                "status_code": getattr(response, "status_code", "N/A"),
                "duration_ms": round(duration * 1000, 2),
                "response_size": response_size,
                "headers": self._sanitize_headers(headers),
            }
            if response_body:
                response_data["body"] = response_body

            if getattr(response, "status_code", 0) >= 500:
                req_logger.error("Request completed with server error", **response_data)
            elif getattr(response, "status_code", 0) >= 400:
                req_logger.warning(
                    "Request completed with client error", **response_data
                )
            else:
                req_logger.info("Request completed successfully", **response_data)

            # Add to span
            span = trace.get_current_span()
            if span:
                span.set_attribute("http.status_code", response_data["status_code"])
                span.set_attribute("duration_ms", response_data["duration_ms"])
        except Exception as e:
            _logger.error(f"Failed to log response: {e}", exc_info=True)

    def _get_client_ip(self, request: Request) -> str:
        return (
            request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or request.headers.get("X-Real-IP")
            or request.headers.get("X-Azure-ClientIP")
            or (request.client.host if request.client else "unknown")
        )

    def _sanitize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        sanitized = {}
        for key, value in headers.items():
            try:
                if key.lower() in self.sensitive_headers:
                    sanitized[key] = (
                        value[:4] + "****" + value[-4:] if len(value) > 8 else "****"
                    )
                else:
                    sanitized[key] = value
            except Exception:
                sanitized[key] = "<error>"
        return sanitized

    def _process_body(self, body: bytes) -> Optional[str]:
        if len(body) > self.max_body_size:
            body = body[: self.max_body_size] + b"..."
        try:
            json_body = json.loads(body)
            return json.dumps(self._sanitize_json_body(json_body))
        except json.JSONDecodeError:
            return body.decode("utf-8", errors="replace")
        except Exception as e:
            return f"<error processing body: {e}>"

    def _sanitize_json_body(self, body: Any) -> Any:
        if isinstance(body, dict):
            return {
                k: (
                    "****"
                    if any(f in k.lower() for f in self.sensitive_json_fields)
                    else (
                        self._sanitize_json_body(v)
                        if isinstance(v, (dict, list))
                        else v
                    )
                )
                for k, v in body.items()
            }
        elif isinstance(body, list):
            return [self._sanitize_json_body(i) for i in body]
        return body
