from pydantic import Field
from src.api.config.base import BaseConfig


class MonitoringSettings(BaseConfig):
    """Monitoring and health check configuration."""
    HEALTH_CHECK_ENABLED: bool = Field(
        default=True, description="Enable health checks")
    HEALTH_CHECK_INTERVAL: int = Field(
        default=30, ge=1, description="Health check interval in seconds")
    METRICS_ENABLED: bool = Field(
        default=True, description="Enable metrics collection")
    PROMETHEUS_ENABLED: bool = Field(
        default=True, description="Enable Prometheus metrics")

    class Config:
        env_prefix = "MONITOR_"
