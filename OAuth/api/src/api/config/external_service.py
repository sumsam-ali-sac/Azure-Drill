from typing import Optional
from pydantic import Field
from src.api.config.base import BaseConfig


class ExternalServiceSettings(BaseConfig):
    """External services configuration."""
    OPENAI_API_KEY: Optional[str] = Field(
        default=None, description="OpenAI API key")

    class Config:
        env_prefix = "EXT_"
