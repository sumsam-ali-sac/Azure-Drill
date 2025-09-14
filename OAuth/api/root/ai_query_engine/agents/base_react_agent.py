from abc import ABC, abstractmethod

from langchain.agents import create_react_agent
from langchain_core.language_models import BaseChatModel
from langchain_core.prompts import (
    ChatPromptTemplate,
    SystemMessagePromptTemplate,
    PromptTemplate,
)
from langchain_core.runnables import Runnable
from langchain_core.tools import Tool

from root.ai_query_engine.agents.base_agent import BaseAgent


class BaseReactAgent(BaseAgent, ABC):
    """
    The BaseReactAgent overrides the default base agent type to use a 'react_agent' invoked using create_react_agent().
    The BaseReactAgent requires that the system prompt be defined using {tools} and {tool_names}
    """

    @abstractmethod
    def get_system_prompt(self) -> str:
        """
        The BaseReactAgent requires that the system prompt be defined using {tools} and {tool_names}
        Example:
        Answer the following questions as best you can. You have access to the following tools:

            {tools}

            Use the following format:

            Question: the input question you must answer
            Thought: you should always think about what to do
            Action: the action to take, should be one of [{tool_names}]
            Action Input: the input to the action
            Observation: the result of the action
            ... (this Thought/Action/Action Input/Observation can repeat N times)
            Thought: I now know the final answer
            Final Answer: the final answer to the original input question

            Begin!

        :return: the system prompt as a string
        """

    def build_agent(
        self,
        llm: BaseChatModel,
        tools: list[Tool],
        prompt_template: ChatPromptTemplate,
        **kwargs
    ) -> Runnable:
        """
        This method provides an optional means to override the creation of the react_agent.

        :param llm: An instance of BaseChatModel representing the language model to be used by the agent.
        :param tools: A list of Tool instances that the agent can use.
        :param prompt_template: A ChatPromptTemplate instance that defines the prompt structure.
        :param kwargs: Additional keyword arguments to be passed to the create_react_agent function.
        :return: A Runnable instance representing the built agent.
        """

        agent = create_react_agent(llm, tools, prompt_template, **kwargs)
        return agent

    def build_system_prompt_template(self) -> SystemMessagePromptTemplate:
        system_prompt = self.get_system_prompt()
        system_prompt_template = SystemMessagePromptTemplate(
            prompt=PromptTemplate(
                input_variables=["tools", "tool_names"], template=system_prompt
            )
        )

        return system_prompt_template

    def build_executor_input(
        self, query: str, session_id: str, filters: dict[str, any]
    ) -> dict[str, any]:
        tools = self.get_tools()
        tool_names = self.get_tool_names()
        return {
            "input": query,
        }
