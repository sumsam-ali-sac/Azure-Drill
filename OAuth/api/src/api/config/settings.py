from functools import lru_cache
from src.api.config.base import BaseConfig
from src.api.config.application import ApplicationSettings
from src.api.config.security import SecuritySettings
from src.api.config.database import DatabaseSettings
from src.api.config.redis import RedisSettings
from src.api.config.azure import AzureSettings
from src.api.config.file import FileSettings
from src.api.config.rate_limit import RateLimitSettings
from src.api.config.cors import CORSSettings
from src.api.config.logging import LoggingSettings
from src.api.config.request_response_logging import RequestResponseLoggingSettings
from src.api.config.performance_monitoring import PerformanceMonitoringSettings
from src.api.config.chat import ChatSettings
from src.api.config.external_service import ExternalServiceSettings
from src.api.config.monitoring import MonitoringSettings
from pydantic import Field


class Settings(BaseConfig):
    """Main settings class that aggregates all application configurations."""
    application: ApplicationSettings = Field(
        default_factory=ApplicationSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    azure: AzureSettings = Field(default_factory=AzureSettings)
    file: FileSettings = Field(default_factory=FileSettings)
    rate_limit: RateLimitSettings = Field(default_factory=RateLimitSettings)
    cors: CORSSettings = Field(default_factory=CORSSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    request_response_logging: RequestResponseLoggingSettings = Field(
        default_factory=RequestResponseLoggingSettings)
    performance_monitoring: PerformanceMonitoringSettings = Field(
        default_factory=PerformanceMonitoringSettings)
    chat: ChatSettings = Field(default_factory=ChatSettings)
    external_service: ExternalServiceSettings = Field(
        default_factory=ExternalServiceSettings)
    monitoring: MonitoringSettings = Field(default_factory=MonitoringSettings)


@lru_cache()
def get_settings() -> Settings:
    """
    Returns a cached instance of the Settings object.
    This ensures settings are loaded only once.
    """
    return Settings()
