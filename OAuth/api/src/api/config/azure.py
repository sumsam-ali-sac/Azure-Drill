from typing import Optional
from pydantic import Field
from src.api.config.base import BaseConfig


class AzureActiveDirectorySettings(BaseConfig):
    AZURE_AD_TENANT_ID: Optional[str] = Field(
        default=None, description="Azure AD tenant ID")
    AZURE_AD_CLIENT_ID: Optional[str] = Field(
        default=None, description="Azure AD client ID")
    AZURE_AD_CLIENT_SECRET: Optional[str] = Field(
        default=None, description="Azure AD client secret")

    class Config:
        env_prefix = "AZURE_AD_"


class AzureStorageSettings(BaseConfig):
    AZURE_STORAGE_CONNECTION_STRING: Optional[str] = Field(
        default=None, description="Azure Storage connection string")
    AZURE_STORAGE_CONTAINER_NAME: str = Field(
        default="chat-files", description="Azure Storage container name")

    class Config:
        env_prefix = "AZURE_STORAGE_"


class AzureAppInsightsSettings(BaseConfig):
    AZURE_APPINSIGHTS_CONNECTION_STRING: Optional[str] = Field(
        default=None, description="Azure App Insights connection string")
    AZURE_APPINSIGHTS_INSTRUMENTATION_KEY: Optional[str] = Field(
        default=None, description="Azure App Insights instrumentation key (legacy)")
    ENABLE_AZURE_MONITORING: bool = Field(
        default=True, description="Enable Azure monitoring via App Insights")

    class Config:
        env_prefix = "AZURE_AI_"


class AzureMonitorSettings(BaseConfig):
    AZURE_MONITOR_WORKSPACE_ID: Optional[str] = Field(
        default=None, description="Azure Monitor workspace ID")
    AZURE_MONITOR_SHARED_KEY: Optional[str] = Field(
        default=None, description="Azure Monitor shared key")

    class Config:
        env_prefix = "AZURE_MONITOR_"


class AzureServiceBusSettings(BaseConfig):
    AZURE_SERVICE_BUS_CONNECTION_STRING: Optional[str] = Field(
        default=None, description="Azure Service Bus connection string")
    AZURE_SERVICE_BUS_QUEUE_NAME: str = Field(
        default="chat-messages", description="Azure Service Bus queue name")

    class Config:
        env_prefix = "AZURE_SB_"


class AzureKeyVaultSettings(BaseConfig):
    AZURE_KEY_VAULT_URL: Optional[str] = Field(
        default=None, description="Azure Key Vault URL")

    class Config:
        env_prefix = "AZURE_KV_"


class AzureSettings(BaseConfig):
    """Azure services configuration."""
    active_directory: AzureActiveDirectorySettings = Field(
        default_factory=AzureActiveDirectorySettings)
    storage: AzureStorageSettings = Field(default_factory=AzureStorageSettings)
    app_insights: AzureAppInsightsSettings = Field(
        default_factory=AzureAppInsightsSettings)
    monitor: AzureMonitorSettings = Field(default_factory=AzureMonitorSettings)
    service_bus: AzureServiceBusSettings = Field(
        default_factory=AzureServiceBusSettings)
    key_vault: AzureKeyVaultSettings = Field(
        default_factory=AzureKeyVaultSettings)

    class Config:
        # This prefix applies to fields directly in AzureSettings, not its nested models
        env_prefix = "AZURE_"
