from langchain_core.messages import HumanMessage, AIMessage
from langchain_core.runnables.base import RunnableLike

from root.ai_query_engine.agents.base_agent import BaseAgent


class AgentNode:
    def __init__(self, agent: BaseAgent):
        self.agent = agent

    @property
    def name(self):
        return self.agent.get_agent_name()

    def __getattr__(self, name):
        return getattr(self.agent, name)

    def create_action(self, query, filters) -> RunnableLike:
        # todo: type state
        def action(state: any):
            result = self.agent.execute(query=query, filters=filters, state=state)

            return {"messages": [AIMessage(content=result, name=self.name)]}

        return action
