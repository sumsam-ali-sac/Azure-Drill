from dotenv import load_dotenv
from langchain_openai import AzureChatOpenAI, AzureOpenAIEmbeddings

from root.ai_query_engine.models.model_settings import (
    LargeLanguageModels,
    BaseModelSettings,
    AzureOpenAIChatSettings,
    EmbeddingModels,
    AzureOpenAIEmbeddingSettings,
)

load_dotenv()


def azure_chat_openai_model_strategy(settings: AzureOpenAIChatSettings):
    return AzureChatOpenAI(
        azure_deployment=settings.azure_deployment,
        temperature=float(settings.temperature),
    )


def azure_openai_embedding_strategy(settings: AzureOpenAIEmbeddingSettings):
    return AzureOpenAIEmbeddings(
        azure_deployment=settings.azure_deployment,
    )


class _LLMFactory:
    def __init__(self):
        self._model_strategies = {
            LargeLanguageModels.AzureOpenAIChat: azure_chat_openai_model_strategy,
            EmbeddingModels.AzureOpenAIEmbedding: azure_openai_embedding_strategy,
        }

    def get_llm(self, settings: BaseModelSettings):
        strategy = self._model_strategies.get(settings.name, None)
        if not strategy:
            raise ValueError(f"Unknown LLM strategy: {settings.name}")
        llm = strategy(settings)
        return llm
