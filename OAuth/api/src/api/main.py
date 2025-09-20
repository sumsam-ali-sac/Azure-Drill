from fastapi import FastAPI, Request
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from contextlib import asynccontextmanager
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.asgi import OpenTelemetryMiddleware
from opentelemetry import trace

from src.api.config import get_settings
from src.api.common.logging import get_logger, get_tracer
from src.api.common.middleware.middleware_factory import (
    create_request_logging_middleware,
)
from src.api.common.middleware.performance_logging import PerformanceLoggingMiddleware
from src.api.common.middleware.security_headers import SecurityHeadersMiddleware
from src.api.routers import health

# ----------------- Settings & Logging ----------------- #
settings = get_settings()
logger = get_logger("uvicorn+" + __name__)
tracer = get_tracer("uvicorn+" + __name__)


# ----------------- Lifespan ----------------- #
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application startup and shutdown."""
    logger.info("Starting application...")
    yield
    logger.info("Shutting down application...")


# ----------------- FastAPI app ----------------- #
app = FastAPI(
    title=settings.application.APP_NAME,
    version=settings.application.VERSION,
    description="A production-grade FastAPI app with tracing/logging.",
    debug=settings.application.DEBUG,
    lifespan=lifespan,
)

# ----------------- Instrumentation ----------------- #
FastAPIInstrumentor.instrument_app(app)

# Use the configured tracer provider (from setup_otel)
app.add_middleware(OpenTelemetryMiddleware, tracer_provider=trace.get_tracer_provider())

# ----------------- Middleware ----------------- #
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(create_request_logging_middleware(log_level="INFO"))
app.add_middleware(PerformanceLoggingMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors.CORS_ORIGINS,
    allow_credentials=settings.cors.CORS_ALLOW_CREDENTIALS,
    allow_methods=settings.cors.CORS_ALLOW_METHODS,
    allow_headers=settings.cors.CORS_ALLOW_HEADERS,
)

if settings.application.ENVIRONMENT == "production":
    app.add_middleware(HTTPSRedirectMiddleware)

app.add_middleware(GZipMiddleware, minimum_size=1000)

# ----------------- Routers ----------------- #
app.include_router(health.router)


# ----------------- Example root endpoint ----------------- #
@app.get("/")
async def read_root(request: Request):
    """Root endpoint returning a welcome message with request ID."""
    with tracer.start_as_current_span("root-endpoint"):
        request_logger = getattr(request.state, "logger", logger)
        request_logger.info("Root endpoint accessed")
        return {
            "message": "Welcome to the API!",
            "request_id": getattr(request.state, "request_id", "none"),
        }
