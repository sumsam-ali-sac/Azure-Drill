import asyncio
import logging
from typing import TypeVar, Generic, Type, Optional, Dict, Any, List
from uuid import UUID

from root.data.data_schemas import PaginatedList
from root.data.sql.base_sql_repository import BaseSqlRepository
from root.data.sql.databricks.base_databricks_sql_model import BaseDatabricksSqlModel

_logger = logging.getLogger(__name__)

TModel = TypeVar("TModel", bound=BaseDatabricksSqlModel)  # orm model


class BaseDatabricksSqlRepository(Generic[TModel], BaseSqlRepository[UUID, TModel]):

    # Databricks sql driver does not support async operations.  So we use the sync methods called within an async wrapper.
    async def get_by_id_async(self, id: UUID) -> Optional[TModel]:
        """
        Retrieve a single object as specified by its primary key.

        :param id: The models primary key (e.g. 'id')
        :return: The model
        """
        return await asyncio.to_thread(self.get_by_id, id)

    async def get_models_by_ids_async(self, ids: list[any]) -> list[TModel]:
        """
        Retrieve multiple objects as specified by their primary keys.
        :param ids: a list of the model's primary keys (e.g., 'id')
        :return: a list of the models
        """
        return await asyncio.to_thread(self.get_models_by_ids, ids)

    async def get_async(
        self,
        query_filter: Optional[Dict[str, Any]] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> List[TModel]:
        """
        Retrieve multiple objects based on query filters, skip, and limit.

        :param query_filter: Dictionary of key-value pairs for filtering the query
        :param skip: Number of records to skip
        :param limit: Maximum number of records to return
        :return: List of models
        """
        return await asyncio.to_thread(self.get, query_filter, skip, limit)

    async def get_paginated_async(
        self,
        query_filter: Optional[Dict[str, Any]] = None,
        skip: int = None,
        limit: int = None,
        order_by: Optional[List[str]] = None,
        search_fields: Optional[List[str]] = None,
        search_text: Optional[str] = None,
    ) -> PaginatedList[TModel]:
        """
        Retrieve a paginated list of objects based on the specified filter
        """
        return await asyncio.to_thread(
            self.get_paginated,
            query_filter,
            skip,
            limit,
            order_by,
            search_fields,
            search_text,
        )

    async def create_async(self, model: TModel, defer_commit: bool = False) -> TModel:
        """
        Create a new model instance and add it to the database asynchronously.
        :param model: The model instance to create
        :param defer_commit: Whether to defer the commit of the transaction
        :return: The created model instance
        """
        return await asyncio.to_thread(self.create, model, defer_commit)

    async def update_async(self, model: TModel, defer_commit: bool = False) -> TModel:
        """
        Update an existing model instance in the database.
        :param model: The model instance to update
        :param defer_commit: Whether to defer the commit of the transaction
        :return: The updated model instance
        """
        return await asyncio.to_thread(self.update, model, defer_commit)

    async def delete_async(self, id: UUID, defer_commit: bool = False) -> None:
        """
        Delete a model instance from the database.
        :param id: The primary key of the model to delete
        :param defer_commit: Whether to defer the commit of the transaction
        """
        return await asyncio.to_thread(self.delete, id, defer_commit)
