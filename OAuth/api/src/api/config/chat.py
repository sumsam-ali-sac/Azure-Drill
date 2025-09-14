from pydantic import Field
from src.api.config.base import BaseConfig


class ChatSettings(BaseConfig):
    """Chat application configuration."""
    MAX_MESSAGE_LENGTH: int = Field(
        default=1000, ge=1, le=10000, description="Maximum message length")
    MAX_ROOM_PARTICIPANTS: int = Field(
        default=100, ge=1, description="Maximum room participants")
    MESSAGE_HISTORY_LIMIT: int = Field(
        default=50, ge=1, description="Message history limit")
    WEBSOCKET_TIMEOUT: int = Field(
        default=300, ge=1, description="WebSocket timeout in seconds")

    class Config:
        env_prefix = "CHAT_"
