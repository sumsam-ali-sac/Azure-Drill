import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from langchain.agents import Tool, AgentExecutor, create_tool_calling_agent
from langchain_core.language_models import BaseChatModel
from langchain_core.prompts import (
    PromptTemplate,
    ChatPromptTemplate,
    SystemMessagePromptTemplate,
    MessagesPlaceholder,
    HumanMessagePromptTemplate,
)
from langchain_core.runnables import Runnable

from root.ai_query_engine.core.base_chat_model_action import BaseChatModelAction
from root.ai_query_engine.models.extensions import OpenAILlmNoStreaming

_logger = logging.getLogger(__name__)


class BaseAgent(BaseChatModelAction, ABC):
    def __init__(self, disable_streaming_response: bool = False):
        """
        The BaseAgent class is an abstract class that provides a template for creating an agent.
        Specifically, this base agent uses langchain's tool_calling_agent to interact with a language model and tools.

        :param disable_streaming_response: For use with OpenAI LLMs only. If True, the llm used by the agent will not return streaming responses.
           This enables the use of token counting callbacks such as OpenAI's get_openai_callback().
        """
        self.disable_streaming_response = disable_streaming_response
        self.agent = self.build_agent(
            self.get_llm(), self.get_tools(), self.build_prompt_template()
        )
        self.agent_executor = None

    @abstractmethod
    def get_agent_name(self) -> str:
        """
        The name of the agent.
        :return: the name of the agent as a string
        """

    @abstractmethod
    def get_tools(self) -> list[Tool]:
        """"""

    def get_tool_names(self) -> list[str]:
        return [tool.name for tool in self.get_tools()]

    def build_system_prompt_template(self) -> SystemMessagePromptTemplate:
        system_prompt = self.get_system_prompt()
        tool_names = self.get_tool_names()
        return SystemMessagePromptTemplate(
            prompt=PromptTemplate(
                input_variables=[
                    "input",
                    "intermediate_steps",
                    tool_names,
                    "agent_scratchpad",
                    "tools",
                ],
                template=system_prompt,
            )
        )

    def build_prompt_template(self) -> ChatPromptTemplate:
        system_prompt_template = self.build_system_prompt_template()

        prompt_template = ChatPromptTemplate.from_messages(
            [
                system_prompt_template,
                MessagesPlaceholder(variable_name="chat_history", optional=True),
                HumanMessagePromptTemplate(
                    prompt=PromptTemplate(input_variables=["input"], template="{input}")
                ),
                MessagesPlaceholder(variable_name="agent_scratchpad"),
            ]
        )

        return prompt_template

    def build_agent(
        self,
        llm: BaseChatModel,
        tools: list[Tool],
        prompt_template: ChatPromptTemplate,
        **kwargs,
    ) -> Runnable:
        """
        This method provides an optional means to override the default agent.
        The default agent is `tool_calling_agent` that is invoked with `create_tool_calling_agent()`
        Example:
            agent = create_tool_calling_agent(llm, tools, prompt_template)
            return agent

        :param llm: The model used by the agent.
        :param tools: The list of tools available to the agent.
        :param prompt_template: A ChatPromptTemplate to use as the prompt.
        :param kwargs: Additional keyword arguments to be passed to the create_react_agent function.
        :return: A Langchain Runnable (agent in this case) to be used with an AgentExecutor.
        """
        if self.disable_streaming_response:
            llm = OpenAILlmNoStreaming(llm)

        agent = create_tool_calling_agent(llm, tools, prompt_template, **kwargs)
        return agent

    def __getattr__(self, name):
        return getattr(self.agent, name)

    def build_executor_input(
        self, query: str, session_id: str = None, filters: dict[str, Any] = None
    ) -> dict[str, Any]:
        """
        This method provides an optional means to override the default object passed to the AgentExecutor invocation.
        :return: the object to be passed to the AgentExecutor invocation.
        """

        return {
            "input": query,
            "tool_names": self.get_tool_names(),
            "tools": self.get_tools(),
        }

    # todo: figure out how to use langchain parsers with agent to parse the final response only
    def parse_output(self, content: str) -> str:
        """
        This method provides an optional means to parse the final string response of the agent
        :param content: the final response output of the agent
        :return:
        """

        return content

    def build_agent_executor(
        self,
        agent: Runnable,
        tools: list[Tool],
        prompt_template: ChatPromptTemplate,
        verbose: bool = True,
        **kwargs,
    ) -> AgentExecutor:
        """
        This method provides an optional means to override the default AgentExecutor.
        The default AgentExecutor is created with `AgentExecutor(agent, tools, verbose=True, handle_parsing_errors=True)`

        :param agent: The agent to be used by the AgentExecutor.
        :param tools: The list of tools available to the agent.
        :param prompt_template: A ChatPromptTemplate to use as the prompt.
        :param kwargs: Additional keyword arguments to be passed to the AgentExecutor.
        :return: An AgentExecutor to be used to invoke the agent.
        """

        return AgentExecutor(
            agent=agent, tools=tools, verbose=verbose, handle_parsing_errors=True
        )

    def execute(
        self,
        query: str,
        session_id: str = None,
        filters: dict[str, Any] = None,
        state=None,
    ):
        input_arg = self.build_executor_input(query, session_id, filters)
        if not self.agent_executor:
            self.agent_executor = self.build_executor()

        response = self.agent_executor.invoke(input_arg, state=state)

        ai_message = f"{response['output']}"
        result = self.parse_output(ai_message)

        return result

    async def execute_async(
        self,
        query: str,
        session_id: str = None,
        filters: dict[str, Any] = None,
        state=None,
    ):
        input_arg = self.build_executor_input(query, session_id, filters)
        if not self.agent_executor:
            self.agent_executor = self.build_executor()

        response = await self.agent_executor.ainvoke(input_arg, state=state)

        ai_message = f"{response['output']}"
        result = self.parse_output(ai_message)

        return result

    def build_executor(self):
        """
        Build and set the agent executor for the current instance. This method initializes the agent executor using the
        agent, tools, and prompt template. The returned executor can be used with various metric frameworks such
        as MLFlow. Generally, the executor should be invoked through the 'execute' and 'execute_async' methods.
        """

        tools = self.get_tools()
        agent = self.agent
        prompt_template = self.build_prompt_template()

        agent_executor = self.build_agent_executor(
            agent=agent, tools=tools, prompt_template=prompt_template
        )

        self.agent_executor = agent_executor

        return agent_executor
