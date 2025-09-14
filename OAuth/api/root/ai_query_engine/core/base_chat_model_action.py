from abc import ABC, abstractmethod

from langchain_core.language_models import BaseChatModel


class BaseChatModelAction(ABC):
    @abstractmethod
    def get_llm(self) -> BaseChatModel:
        """
        example: return llm_factory.get_llm(HuggingFaceModelSettings(
            model_id=engine_settings.hugging_face_model_id,
            max_tokens=engine_settings.hugging_face_max_tokens
        ))
        :return:
        """

    @abstractmethod
    def get_system_prompt(self) -> str:
        """
        Define and return a prompt to be given to the chat model as system prompt.
        :return: the system prompt as a string
        """
