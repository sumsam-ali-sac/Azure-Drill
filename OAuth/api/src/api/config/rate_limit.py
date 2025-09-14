from pydantic import Field
from src.api.config.base import BaseConfig


class RateLimitSettings(BaseConfig):
    """Rate limiting configuration."""
    RATE_LIMIT_REQUESTS: int = Field(
        default=100, ge=1, description="Rate limit requests per window")
    RATE_LIMIT_WINDOW: int = Field(
        default=60, ge=1, description="Rate limit window in seconds")
    RATE_LIMIT_ENABLED: bool = Field(
        default=True, description="Enable rate limiting")

    class Config:
        env_prefix = "RATE_"
