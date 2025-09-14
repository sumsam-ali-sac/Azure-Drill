import logging
from abc import ABC, abstractmethod
from typing import TypedDict, Type

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import HumanMessage
from langchain_core.prompts import (
    ChatPromptTemplate,
    MessagesPlaceholder,
    BasePromptTemplate,
)
from langgraph.graph import StateGraph

from root.ai_query_engine.agents.base_agent import BaseAgent
from root.ai_query_engine.graphs.agent_node import AgentNode


# TODO: The BaseGraphEngine is a work in progress
class BaseGraphEngine(ABC):
    @abstractmethod
    def get_agents(self) -> list[BaseAgent]:
        """"""

    @abstractmethod
    def add_workflow_edges(self, workflow: StateGraph) -> None:
        """
        Add workflow edges to the StateGraph workflow if required.  If not required, simply pass.
        example:
        workflow.add_edge(agent1.name, agent2.name)
        :param workflow:
        :return: None
        """

    @abstractmethod
    def build_state_schema(self) -> Type[TypedDict]:
        """
        Defines and returns a TypedDict class representing the state of an agent.

        Example:
            from langgraph.graph.message import add_messages

            class AgentState(TypedDict):
                messages: Annotated[Sequence[BaseMessage], add_messages]
                next: str

            return AgentState
        :return: A TypedDict class representing the state of an agent.
        """

    @abstractmethod
    def format_result(self, response: dict[str, any]) -> any:
        """"""

    @abstractmethod
    def set_entry_point(self, workflow: StateGraph) -> None:
        """"""

    @abstractmethod
    def set_finish_point(self, workflow: StateGraph) -> None:
        """"""

    @abstractmethod
    def get_system_prompt(self) -> str:
        """"""

    def add_conditional_edges(self, workflow: StateGraph) -> None:
        pass

    @property
    def model_temperature(self) -> float:
        return 0.7

    @abstractmethod
    def get_llm(self) -> BaseChatModel:
        """"""

    def run(self, query: str, filters: dict[str, any] | None = None) -> str:
        filters = filters or {}
        logging.info(f"Processing query: {query}.")

        # todo: likely change name
        workers = [agent.get_agent_name() for agent in self.get_agents()]

        # todo: rename 'options'
        options = ["FINISH"] + workers

        prompt = self.build_prompt_template(options, workers)

        # todo: ability to set model functions
        # openai_functions = self.get_openai_functions(options)

        llm = self.get_llm()

        state_schema = self.build_state_schema()

        workflow = StateGraph(state_schema)
        for agent in self.get_agents():
            agent_node = AgentNode(agent)
            agent_action = agent_node.create_action(query=query, filters=filters)
            workflow.add_node(agent_node.name, agent_action)

        self.add_workflow_edges(workflow)
        self.add_conditional_edges(workflow)
        self.set_entry_point(workflow)
        self.set_finish_point(workflow)
        graph = workflow.compile()

        inputs = {"messages": [HumanMessage(content=query)]}
        response = graph.invoke(inputs)
        formatted_result = self.format_result(response)

        return formatted_result

    def build_prompt_template(
        self, options: list[str], workers: list[str]
    ) -> BasePromptTemplate:
        # todo: can we remove the partial?  how do we let people know that 'options' and 'workers' are available for their agent prompts
        prompt = ChatPromptTemplate.from_messages(
            [
                ("system", self.get_system_prompt()),
                MessagesPlaceholder(variable_name="messages"),
                (
                    "system",
                    "Given the conversation above, who should act next?"
                    " Or should we FINISH? Select one of: {options}"
                    " If you are unsure of what to do then select FINISH.",
                ),
            ]
        ).partial(options=str(options), workers=", ".join(workers))

        return prompt
