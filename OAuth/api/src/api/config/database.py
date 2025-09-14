from pydantic import Field, field_validator
from src.api.config.base import BaseConfig


class DatabaseSettings(BaseConfig):
    """Database configuration."""
    DATABASE_URL: str = Field(description="Database connection URL")
    DATABASE_POOL_SIZE: int = Field(
        default=10, ge=1, description="Database connection pool size")
    DATABASE_MAX_OVERFLOW: int = Field(
        default=20, ge=0, description="Database max overflow connections")
    DATABASE_POOL_TIMEOUT: int = Field(
        default=30, ge=1, description="Database pool timeout in seconds")
    DATABASE_POOL_RECYCLE: int = Field(
        default=3600, ge=1, description="Database pool recycle time in seconds")

    @field_validator("DATABASE_URL")
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        if not v.startswith(("postgresql://", "sqlite://", "mysql://")):
            raise ValueError(
                "Database URL must start with postgresql://, sqlite://, or mysql://")
        return v

    class Config:
        env_prefix = "DB_"
