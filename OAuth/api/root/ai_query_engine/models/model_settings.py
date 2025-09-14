from abc import ABC
from enum import Enum

from openai import BaseModel


class LargeLanguageModels(str, Enum):
    AzureOpenAIChat = "AzureOpenAIChat"


class EmbeddingModels(str, Enum):
    AzureOpenAIEmbedding = "AzureOpenAIEmbedding"


class BaseModelSettings(BaseModel, ABC):
    name: LargeLanguageModels | EmbeddingModels


class AzureOpenAIChatSettings(BaseModelSettings):
    name: LargeLanguageModels = LargeLanguageModels.AzureOpenAIChat
    azure_deployment: str
    temperature: float


class AzureOpenAIEmbeddingSettings(BaseModelSettings):
    name: LargeLanguageModels = EmbeddingModels.AzureOpenAIEmbedding
    azure_deployment: str