from pydantic import Field, field_validator
from src.api.config.base import BaseConfig


class ApplicationSettings(BaseConfig):
    """Core application configuration."""
    APP_NAME: str = Field(default="FastAPI Chat Application",
                          description="Application name")
    VERSION: str = Field(default="1.0.0", description="Application version")
    ENVIRONMENT: str = Field(
        default="development", description="Environment (development/staging/production)")
    DEBUG: bool = Field(default=False, description="Debug mode")
    HOST: str = Field(default="0.0.0.0", description="Host to bind to")
    PORT: int = Field(default=8000, ge=1, le=65535,
                      description="Port to bind to")

    @field_validator("ENVIRONMENT")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        allowed = ["development", "staging", "production"]
        if v not in allowed:
            raise ValueError(f"Environment must be one of {allowed}")
        return v

    class Config:
        env_prefix = "APP_"
