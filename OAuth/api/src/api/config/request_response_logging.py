from typing import List
from pydantic import Field
from src.api.config.base import BaseConfig


class RequestResponseLoggingSettings(BaseConfig):
    """Settings for RequestLoggingMiddleware and AzureRequestLoggingMiddleware."""
    LOG_REQUEST_BODY: bool = Field(
        default=False, description="Enable logging of request bodies")
    LOG_RESPONSE_BODY: bool = Field(
        default=False, description="Enable logging of response bodies")
    MAX_BODY_SIZE: int = Field(
        default=1024, description="Max bytes to log for request/response bodies")
    SKIP_PATHS: List[str] = Field(
        default=["/health", "/metrics"], description="Paths to skip request logging for")
    SENSITIVE_HEADERS: List[str] = Field(
        default=[
            "authorization", "cookie", "x-api-key", "x-ms-client-request-id",
            "x-ms-correlation-request-id", "x-ms-subscription-id"
        ],
        description="Headers whose values should be masked in logs"
    )
    SENSITIVE_JSON_FIELDS: List[str] = Field(
        default=["password", "token", "secret", "key", "auth"],
        description="JSON fields whose values should be masked in logs"
    )

    class Config:
        env_prefix = "REQ_LOG_"
