from abc import ABC, abstractmethod
from typing import TypeVar, Generic, Type

from langchain_core.output_parsers import BaseOutputParser, StrOutputParser
from langchain_core.prompts import BasePromptTemplate

from root.ai_query_engine.core.base_chat_model_action import BaseChatModelAction

TQuery = TypeVar("TQuery", bound=object)


class BaseChain(Generic[TQuery], BaseChatModelAction, ABC):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.chain = None

    @property
    def output_parser(self) -> BaseOutputParser:
        """
        Returns a default output parser of type StrOutputParser
        :return:
        """

        parser = self.get_output_parser()
        return parser()

    def get_output_parser(self) -> Type[BaseOutputParser]:
        return StrOutputParser

    @abstractmethod
    def build_prompt_template(
        self, query: TQuery, session_id: str
    ) -> BasePromptTemplate:
        """"""

    @abstractmethod
    def get_chain_input(self, query: TQuery, session_id: str = None) -> object:
        """"""

    def post_processing(self, query: TQuery, response: any, session_id: str = None):
        return None

    def execute(self, query: TQuery, session_id: str = None) -> any:
        if not self.chain:
            self.chain = self.build_chain(query, session_id)

        chain_input = self.get_chain_input(query, session_id)

        response = self.chain.invoke(chain_input)

        self.post_processing(query, response, session_id)

        return response

    async def execute_async(self, query: TQuery, session_id: str = None) -> any:
        if not self.chain:
            self.chain = self.build_chain(query, session_id)

        chain_input = self.get_chain_input(query, session_id)

        response = await self.chain.ainvoke(chain_input)

        self.post_processing(query, response, session_id)

        return response

    def build_chain(self, query: TQuery, session_id: str = None):
        """
        Build and set the chain for the current instance.  This method returns the chain as well to be used with various
        metric frameworks such as MLFlow.  In general, the chain should not be executed directly, but rather through the
        'execute' and 'execute_async' methods.
        """

        llm = self.get_llm()
        prompt_template = self.build_prompt_template(session_id=session_id, query=query)
        output_parser = self.output_parser

        chain = prompt_template | llm | output_parser

        self.chain = chain

        return chain
