from pydantic import Field, field_validator
from src.api.config.base import BaseConfig


class SecuritySettings(BaseConfig):
    """Security and authentication configuration."""
    SECRET_KEY: str = Field(
        min_length=32, description="Secret key for JWT tokens")
    ALGORITHM: str = Field(default="HS256", description="JWT algorithm")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(
        default=30, ge=1, description="Access token expiration in minutes")
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(
        default=7, ge=1, description="Refresh token expiration in days")

    @field_validator("SECRET_KEY")
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("Secret key must be at least 32 characters long")
        return v

    class Config:
        env_prefix = "SECURITY_"
