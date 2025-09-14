from typing import List
from pydantic import Field
from src.api.config.base import BaseConfig


class FileSettings(BaseConfig):
    """File upload configuration."""
    MAX_FILE_SIZE: int = Field(
        default=10 * 1024 * 1024, ge=1, description="Maximum file size in bytes")
    ALLOWED_FILE_TYPES: List[str] = Field(
        default=[".jpg", ".jpeg", ".png", ".gif",
                 ".pdf", ".txt", ".doc", ".docx"],
        description="Allowed file extensions"
    )

    class Config:
        env_prefix = "FILE_"
