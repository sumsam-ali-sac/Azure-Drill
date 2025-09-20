from pydantic import Field
from pydantic_settings import BaseSettings


class JaegerOtelSettings(BaseSettings):
    JAEGER_ENDPOINT: str = Field(
        default=None,
        description="Default Jaeger endpoint for Otel telemetry export",
    )

    class Config:
        env_prefix = "OTEL_"
