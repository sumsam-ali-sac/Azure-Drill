from typing import Optional

from dotenv import load_dotenv
from langchain.tools import Tool
from langchain.tools.retriever import create_retriever_tool
from langchain_community.vectorstores import AzureCosmosDBVectorSearch
from pydantic import BaseModel, PrivateAttr
from pymongo import MongoClient
from pymongo.collection import Collection

from root.ai_query_engine.configuration.settings import engine_settings
from root.ai_query_engine.models.model_settings import AzureOpenAIEmbeddingSettings
from root.ai_query_engine.util import llm_factory

load_dotenv()


class CosmosVCoreRetriever(BaseModel):
    mongo_client: MongoClient
    db_name: str
    collection_name: str
    vector_search_index_name: str
    _mongodb_collection: Collection = PrivateAttr()
    _vector_store: AzureCosmosDBVectorSearch = PrivateAttr()

    class Config:
        arbitrary_types_allowed = True

    def __init__(self, **data) -> None:
        super().__init__(**data)
        self._mongodb_collection = self.mongo_client[self.db_name][self.collection_name]

        embedding = llm_factory.get_llm(
            AzureOpenAIEmbeddingSettings(
                azure_deployment=engine_settings.azure_embedding_deployment_name,
            )
        )
        self._vector_store = AzureCosmosDBVectorSearch(
            collection=self._mongodb_collection,
            embedding=embedding,
            index_name=self.vector_search_index_name,
            text_key="text_content",
            embedding_key="vector_content",
        )

    def get_retriever(self, search_type="similarity", **search_kwargs):
        """
        Get the retriever object
        :param search_type: The type of search to perform
        :param search_kwargs: The search arguments
        :return: The retriever object
        """
        return self._vector_store.as_retriever(
            search_type=search_type, search_kwargs=search_kwargs
        )

    def get_data_threshold(
        self, query: str, k: Optional[int] = 5, score_threshold: Optional[float] = 0.0
    ):
        """
        Get data from the vector store with a score threshold
        :param query: The query to search for
        :param k: The number of results to return
        :param score_threshold: The score threshold
        :return: The data
        """
        return self._vector_store.similarity_search_with_score(
            query=query, k=k, score_threshold=score_threshold
        )

    def get_retriever_tool(self, retriever, tool_name: str, description: str) -> Tool:
        """
        Create a retriever tool from the retriever
        :param retriever: The retriever object
        :param tool_name: The name of the tool
        :param description: The description of the tool
        :return: The tool object and a list containing the tool object
        """
        tool = create_retriever_tool(
            retriever,
            tool_name,
            description,
        )
        return tool
