from typing import Optional
from pydantic import Field, field_validator
from src.api.config.base import BaseConfig


class LoggingSettings(BaseConfig):
    """Logging configuration."""
    LOG_LEVEL: str = Field(default="INFO", description="Logging level")
    LOG_FORMAT: str = Field(
        default="json", description="Log format (json/detailed/simple)")
    LOG_FILE: Optional[str] = Field(default=None, description="Log file path")
    LOG_ROTATION: str = Field(
        default="1 day", description="Log rotation interval")
    LOG_RETENTION: str = Field(
        default="30 days", description="Log retention period")

    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        allowed = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in allowed:
            raise ValueError(f"Log level must be one of {allowed}")
        return v.upper()

    @field_validator("LOG_FORMAT")
    @classmethod
    def validate_log_format(cls, v: str) -> str:
        allowed = ["json", "detailed", "simple"]
        if v not in allowed:
            raise ValueError(f"Log format must be one of {allowed}")
        return v

    class Config:
        env_prefix = "LOG_"
