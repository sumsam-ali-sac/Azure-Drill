from typing import TypeVar, Generic, Optional, Any

from root.data.data_schemas import PaginatedList
from root.data.nosql.mongo.base_mongo_model import BaseMongoModel
from root.data.nosql.mongo.base_mongo_repository import BaseMongoRepository

TId = TypeVar("TId", bound=any)  # primary key type, e.g., str or ObjectId
TModel = TypeVar("TModel", bound=BaseMongoModel)


class BaseMongoManager(Generic[TId, TModel]):
    """
    Base class for MongoDB managers.
    Provides basic CRUD operations and pagination.
    """

    def __init__(self, repository: BaseMongoRepository[TId, TModel]):
        self._repository = repository

    def create(self, model: TModel) -> TModel:
        """
        Create a new document in the collection.
        """
        return self._repository.create(model)

    async def create_async(self, model: TModel) -> TModel:
        """
        Asynchronously create a new document in the collection.
        """
        return await self._repository.create_async(model)

    def get_by_id(self, id: TId) -> TModel:
        """
        Get a document by its ID.
        """
        return self._repository.get_by_id(id)

    async def get_by_id_async(self, id: TId) -> TModel:
        """
        Asynchronously get a document by its ID.
        """
        return await self._repository.get_by_id_async(id)

    def get(
        self, filter: Optional[dict] = None, skip: int = 0, limit: int = 50
    ) -> list[TModel]:
        """
        Get documents with optional filtering, pagination, and sorting.
        """
        return self._repository.get(filter=filter, skip=skip, limit=limit)

    async def get_async(
        self, filter: Optional[dict] = None, skip: int = 0, limit: int = 50
    ) -> list[TModel]:
        """
        Asynchronously get documents with optional filtering, pagination, and sorting.
        """
        return await self._repository.get_async(filter=filter, skip=skip, limit=limit)

    def get_many_by_id(self, ids: list[TId]) -> list[TModel]:
        """
        Get multiple documents by their IDs.
        """
        return self._repository.get_many_by_id(ids)

    async def get_many_by_id_async(self, ids: list[TId]) -> list[TModel]:
        """
        Asynchronously get multiple documents by their IDs.
        """
        return await self._repository.get_many_by_id_async(ids)

    def count(self, filter: Optional[dict] = None) -> int:
        """
        Count documents that match the given filter.
        """
        return self._repository.count(filter)

    async def count_async(self, filter: Optional[dict] = None) -> int:
        """
        Asynchronously count documents that match the given filter.
        """
        return await self._repository.count_async(filter)

    def get_paginated(
        self,
        query_filter: Optional[dict[str, Any]] = None,
        skip: Optional[int] = None,
        limit: Optional[int] = None,
        order_by: Optional[list[str]] = None,
        search_fields: Optional[list[str]] = None,
        search_text: Optional[str] = None,
    ) -> PaginatedList[TModel]:
        """
        Get a paginated list of documents with optional filtering, sorting, and searching.
        """
        return self._repository.get_paginated(
            query_filter=query_filter,
            skip=skip,
            limit=limit,
            order_by=order_by,
            search_fields=search_fields,
            search_text=search_text,
        )

    async def get_paginated_async(
        self,
        query_filter: Optional[dict[str, Any]] = None,
        skip: Optional[int] = None,
        limit: Optional[int] = None,
        order_by: Optional[list[str]] = None,
        search_fields: Optional[list[str]] = None,
        search_text: Optional[str] = None,
    ) -> PaginatedList[TModel]:
        """
        Asynchronously get a paginated list of documents with optional filtering, sorting, and searching.
        """
        return await self._repository.get_paginated_async(
            query_filter=query_filter,
            skip=skip,
            limit=limit,
            order_by=order_by,
            search_fields=search_fields,
            search_text=search_text,
        )

    def update(self, model: TModel) -> TModel:
        """
        Update an existing document by its ID.
        """
        return self._repository.update(model)

    async def update_async(self, model: TModel) -> TModel:
        """
        Asynchronously update an existing document by its ID.
        """
        return await self._repository.update_async(model)

    def delete(self, id: TId) -> None:
        """
        Delete a document by its ID.
        Returns True if the document was deleted, False otherwise.
        """
        return self._repository.delete(id)

    async def delete_async(self, id: TId) -> None:
        """
        Asynchronously delete a document by its ID.
        Returns True if the document was deleted, False otherwise.
        """
        return await self._repository.delete_async(id)
