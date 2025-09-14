from langchain_community.vectorstores import AzureCosmosDBVectorSearch
from pydantic import BaseModel, PrivateAttr
from pymongo import MongoClient
from pymongo.collection import Collection


from dotenv import load_dotenv

from root.ai_query_engine.models.model_settings import AzureOpenAIEmbeddingSettings
from root.ai_query_engine.util import llm_factory

load_dotenv()


# todo: WORK IN PROGRESS
class _CosmosVCoreRetriever(BaseModel):
    """
    WORK IN PROGRESS
    """

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
                azure_deployment="ada002Deployment",
            )
        )
        self._vector_store = AzureCosmosDBVectorSearch(
            collection=self._mongodb_collection,
            embedding=embedding,
            index_name=self.vector_search_index_name,
            text_key="text_content",
            embedding_key="vector_content",
        )

    def get_retriever(self):
        pass

    def get_data(self, query: str, **kwargs):
        return self._vector_store.similarity_search_with_score(query=query)
