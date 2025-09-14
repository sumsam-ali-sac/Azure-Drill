from pydantic import Field
from src.api.config.base import BaseConfig


class PerformanceMonitoringSettings(BaseConfig):
    """Settings for PerformanceLoggingMiddleware."""
    SLOW_REQUEST_THRESHOLD: float = Field(
        default=1.0, description="Threshold in seconds for logging slow requests")

    class Config:
        env_prefix = "PERF_MON_"
