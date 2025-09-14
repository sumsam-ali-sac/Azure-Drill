from abc import ABC
from typing import TypedDict

from langchain_core.messages import BaseMessage, HumanMessage
from langchain_core.prompts import (
    MessagesPlaceholder,
    BasePromptTemplate,
    ChatPromptTemplate,
)
from typing_extensions import NotRequired

from root.ai_query_engine.chains.base_chain import BaseChain
from root.ai_query_engine.util.memory_cache import MemoryCache

memory_cache = MemoryCache()


class ChatQuery(TypedDict):
    input: str
    chat_history: NotRequired[list[BaseMessage]]


class BaseChatChain(BaseChain[ChatQuery], ABC):
    def get_chain_input(self, query: ChatQuery, session_id: str = None) -> object:
        messages = query.get("chat_history", [])
        messages.append(HumanMessage(content=query.get("input", "")))

        return messages

    def build_prompt_template(
        self, query: ChatQuery, session_id: str
    ) -> BasePromptTemplate:
        prompt_template = ChatPromptTemplate.from_messages(
            [
                ("system", self.get_system_prompt()),
                MessagesPlaceholder(variable_name="message_history"),
            ]
        )

        return prompt_template
