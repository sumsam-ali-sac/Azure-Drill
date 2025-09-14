from typing import Optional
from pydantic import Field
from src.api.config.base import BaseConfig


class RedisSettings(BaseConfig):
    """Redis configuration."""
    REDIS_URL: str = Field(default="redis://localhost:6379/0",
                           description="Redis connection URL")
    REDIS_POOL_SIZE: int = Field(
        default=10, ge=1, description="Redis connection pool size")
    REDIS_TIMEOUT: int = Field(
        default=5, ge=1, description="Redis timeout in seconds")
    AZURE_REDIS_CONNECTION_STRING: Optional[str] = Field(
        default=None, description="Azure Redis connection string (primary for Azure deployments)")

    class Config:
        env_prefix = "REDIS_"
