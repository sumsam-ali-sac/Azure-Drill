from typing import List
from pydantic import Field, field_validator
from src.api.config.base import BaseConfig


class CORSSettings(BaseConfig):
    """CORS configuration."""
    CORS_ORIGINS: List[str] = Field(
        default=["http://localhost:3000", "http://localhost:8000"],
        description="Allowed CORS origins"
    )
    CORS_ALLOW_CREDENTIALS: bool = Field(
        default=True, description="Allow CORS credentials")
    CORS_ALLOW_METHODS: List[str] = Field(
        default=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        description="Allowed CORS methods"
    )
    CORS_ALLOW_HEADERS: List[str] = Field(
        default=["*"], description="Allowed CORS headers")

    @field_validator("CORS_ORIGINS")
    @classmethod
    def validate_cors_origins(cls, v: List[str]) -> List[str]:
        for origin in v:
            if not origin.startswith(("http://", "https://")) and origin != "*":
                raise ValueError(f"Invalid CORS origin: {origin}")
        return v

    class Config:
        env_prefix = "CORS_"
