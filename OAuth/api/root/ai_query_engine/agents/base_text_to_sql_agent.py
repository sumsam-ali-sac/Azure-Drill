from abc import ABC, abstractmethod

from langchain.agents import AgentExecutor
from langchain_community.agent_toolkits import create_sql_agent
from langchain_community.utilities import SQLDatabase
from langchain_core.language_models import BaseChatModel
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import Runnable
from langchain_core.tools import Tool

from root.ai_query_engine.agents.base_agent import BaseAgent


class BaseTextToSQLAgent(BaseAgent, ABC):

    @abstractmethod
    def get_database_uri(self) -> str:
        pass

    def get_tool_names(self) -> list[str]:
        pass

    def get_db(self) -> SQLDatabase:
        return SQLDatabase.from_uri(self.get_database_uri())

    def get_tools(self) -> list[Tool]:
        pass

    def build_agent(
        self,
        llm: BaseChatModel,
        tools: list[Tool],
        prompt_template: ChatPromptTemplate,
        **kwargs
    ) -> Runnable:
        pass

    def build_agent_executor(
        self,
        agent: Runnable,
        tools: list[Tool],
        prompt_template: ChatPromptTemplate,
        verbose: bool = True,
        **kwargs
    ) -> AgentExecutor:
        llm = self.get_llm()
        db = self.get_db()
        agent_executor = create_sql_agent(
            llm, db=db, agent_type="openai-tools", verbose=True
        )

        return agent_executor

    def build_executor_input(
        self, query: str, session_id: str = None, filters: dict[str, any] = None
    ) -> dict[str, any]:
        return {
            "agent_scratchpad": "",
            "input": query,
        }


# Define the connection string
# connection_url = URL.create(
#     "mssql+pyodbc",
#     username="sa",
#     password="Pass@word@219",
#     host="127.0.0.1",
#     port=1433,
#     database="Northwind",
#     query={
#         "driver": "ODBC Driver 17 for SQL Server",
#         "Encrypt": "yes",
#         "TrustServerCertificate": "yes",
#     },
# )
#
# db = SQLDatabase.from_uri(connection_url)
# llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
# agent_executor = create_sql_agent(llm, db=db, agent_type="openai-tools", verbose=True)
#
# # Streamlit app layout
# st.title('NL 2 SQL')
#
# # User input
# user_query = st.text_area("Enter your query:", "What are the top selling products?")
#
# if st.button('Submit'):
#     try:
#         # Processing user input
#         response = agent_executor.invoke({
#             "agent_scratchpad": "",
#             "input": user_query,
#         }, config={"callbacks": [langfuse_handler]})
#         st.write("Response:")
#         st.json(response)
#     except Exception as e:
#         st.error(f"An error occurred: {e}")
