from langchain_openai import AzureChatOpenAI

from root.ai_query_engine.models.model_settings import (
    AzureOpenAIChatSettings,
    AzureOpenAIEmbeddingSettings,
)
from root.ai_query_engine.util import llm_factory


def get_azure_openai_chat_model(
    azure_deployment: str, temperature: float = 0.7
) -> AzureChatOpenAI:
    """
    Return an instance of a langchain AzureChatOpenAI model.
    :param azure_deployment: The name of the azure model deployment.
    :param temperature: The model temperature.
    :return:
    """
    return llm_factory.get_llm(
        AzureOpenAIChatSettings(
            azure_deployment=azure_deployment, temperature=temperature
        )
    )


def get_azure_openai_embedding_model(
    azure_deployment: str,
) -> AzureOpenAIEmbeddingSettings:
    return llm_factory.get_llm(
        AzureOpenAIEmbeddingSettings(azure_deployment=azure_deployment)
    )
