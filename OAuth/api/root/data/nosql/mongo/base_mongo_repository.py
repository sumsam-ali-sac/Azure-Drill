import logging
from abc import ABC, abstractmethod
from typing import TypeVar, Generic, Type, Optional, Any

from pymongo.asynchronous.database import AsyncDatabase
from pymongo.synchronous.database import Database

from root.core.util.datetime_helpers import utc_now_time_aware
from root.data.data_schemas import PaginatedList
from root.data.nosql.mongo.base_mongo_model import BaseMongoModel

_logger = logging.getLogger(__name__)

TId = TypeVar("TId", bound=any)  # primary key type, e.g., str or ObjectId
TModel = TypeVar("TModel", bound=BaseMongoModel)


class BaseMongoRepository(Generic[TModel, TId], ABC):
    """
    Base repository class for MongoDB operations.
    This class provides a generic interface for CRUD operations on MongoDB collections.
    """

    def __init__(self, db: Database = None, db_async: AsyncDatabase = None):
        """
        Initialize the repository with MongoDB clients.

        :param db: Synchronous MongoDB client database.
        :param db_async: Asynchronous MongoDB client database.
        """
        if db is None and db_async is None:
            raise ValueError("At least one of 'db' or 'db_async' must be provided.")

        if db is not None:
            self._collection = db[self.get_collection_name()]

        if db_async is not None:
            self._collection_async = db_async[self.get_collection_name()]

    @classmethod
    @abstractmethod
    def get_collection_name(cls) -> str:
        """
        Returns the name of the MongoDB collection.
        Must be implemented by subclasses.
        """
        raise NotImplementedError(
            "Subclasses must implement get_collection_name method."
        )

    @property
    @abstractmethod
    def _model(self) -> Type[TModel]:
        """
        Returns the Pydantic model class associated with this repository.
        Must be implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement _model property.")

    @abstractmethod
    def generate_id(self) -> TId:
        """
        Generate a new unique identifier for the model.
        This method should be implemented to return a unique ID for the model.
        """
        pass

    def get_by_id(self, id: TId) -> TModel | None:
        """
        Retrieve a single object as specified by its 'id' field.

         :param id: The unique identifier of the object to retrieve.
         :return: An instance of TModel if found, otherwise None.
        """
        doc = self._collection.find_one({"id": id})
        if doc:
            return self._model.model_validate(doc)

        return None

    async def get_by_id_async(self, id: TId) -> TModel | None:
        """
        Asynchronously retrieve a single object as specified by its 'id' field.

        :param id: The unique identifier of the object to retrieve.
        :return: An instance of TModel if found, otherwise None.
        """
        doc = await self._collection_async.find_one({"id": id})
        if doc:
            return self._model.model_validate(doc)

        return None

    def get_many_by_id(self, ids: list[TId]) -> list[TModel]:
        """
        Retrieve multiple objects by their 'id' fields.

        :param ids: A list of unique identifiers for the objects to retrieve.
        :return: A list of TModel instances.
        """
        cursor = self._collection.find({"id": {"$in": ids}})
        return [self._model.model_validate(doc) for doc in cursor]

    async def get_many_by_id_async(self, ids: list[TId]) -> list[TModel]:
        """
        Asynchronously retrieve multiple objects by their 'id' fields.

        :param ids: A list of unique identifiers for the objects to retrieve.
        :return: A list of TModel instances.
        """
        cursor = self._collection_async.find({"id": {"$in": ids}})
        return [self._model.model_validate(doc) async for doc in cursor]

    def get(
        self, filter: Optional[dict] = None, limit: int = 0, skip: int = 0
    ) -> list[TModel]:
        """
        Retrieve multiple objects based on a filter.

        :param filter: A dictionary representing the filter criteria.
        :param limit: The maximum number of documents to return.
        :param skip: The number of documents to skip.
        :return: A list of TModel instances.
        """
        if filter is None:
            filter = {}

        cursor = self._collection.find(filter).limit(limit).skip(skip)
        return [self._model.model_validate(doc) for doc in cursor]

    async def get_async(
        self, filter: Optional[dict] = None, limit: int = 0, skip: int = 0
    ) -> list[TModel]:
        """
        Asynchronously retrieve multiple objects based on a filter.

        :param filter: A dictionary representing the filter criteria.
        :param limit: The maximum number of documents to return.
        :param skip: The number of documents to skip.
        :return: A list of TModel instances.
        """
        if filter is None:
            filter = {}

        cursor = self._collection_async.find(filter).skip(skip)
        if limit:
            cursor = cursor.limit(limit)
        return [self._model.model_validate(doc) async for doc in cursor]

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
        Retrieve multiple objects (synchronously) based on filters, pagination, ordering, and search.
        """

        # 1. Build filter dict
        mongo_filter = dict(query_filter) if query_filter else {}

        # 2. Add search, if provided
        if search_text and search_fields:
            regex = {"$regex": search_text, "$options": "i"}
            mongo_filter["$or"] = [{field: regex} for field in search_fields]

        # 3. Get total count of results
        total = self._collection.count_documents(mongo_filter)

        # 4. Build cursor
        cursor = self._collection.find(mongo_filter)

        cursor, skip_val, limit_val = self._order_skip_limit(
            cursor, order_by, skip, limit, total
        )

        # 7. Fetch and parse
        data = [self._model.model_validate(doc) for doc in cursor]

        # 8. Pagination calculation
        next_page = skip_val + limit_val if skip_val + limit_val < total else None
        previous_page = skip_val - limit_val if skip_val - limit_val >= 0 else None

        return PaginatedList(
            total=total,
            skip=skip_val,
            limit=limit_val,
            data=data,
            next=next_page,
            previous=previous_page,
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
        Asynchronously retrieve multiple objects based on filters, pagination, ordering, and search.
        """

        # 1. Build filter dict
        mongo_filter = dict(query_filter) if query_filter else {}

        # 2. Add search, if provided
        if search_text and search_fields:
            regex = {"$regex": search_text, "$options": "i"}
            mongo_filter["$or"] = [{field: regex} for field in search_fields]

        # 3. Get total count of results
        total = await self._collection_async.count_documents(mongo_filter)

        # 4. Build cursor
        cursor = self._collection_async.find(mongo_filter)

        cursor, skip_val, limit_val = self._order_skip_limit(
            cursor, order_by, skip, limit, total
        )

        # 7. Fetch and parse data
        docs = [doc async for doc in cursor]
        data = [self._model.model_validate(doc) for doc in docs]

        # 8. Pagination calculation
        next_page = skip_val + limit_val if skip_val + limit_val < total else None
        previous_page = skip_val - limit_val if skip_val - limit_val >= 0 else None

        return PaginatedList(
            total=total,
            skip=skip_val,
            limit=limit_val,
            data=data,
            next=next_page,
            previous=previous_page,
        )

    def count(self, filter: Optional[dict] = None) -> int:
        """
        Count documents that match the given filter.

        :param filter: A dictionary representing the filter criteria. If None, counts all documents.
        :return: The number of documents matching the filter.
        """
        if filter is None:
            filter = {}

        return self._collection.count_documents(filter)

    async def count_async(self, filter: Optional[dict] = None) -> int:
        """
        Asynchronously count documents that match the given filter.

        :param filter: A dictionary representing the filter criteria. If None, counts all documents.
        :return: The number of documents matching the filter.
        """
        if filter is None:
            filter = {}

        return await self._collection_async.count_documents(filter)

    def create(self, model: TModel) -> TModel:
        """
        Create a new model instance and add it to the MongoDB collection.
        :param model: The model instance to create
        :return: The created model instance (with _id/object_id if generated by Mongo)
        """
        self._set_id(model)
        self._set_or_update_timestamps(model)
        doc = model.model_dump(by_alias=True)

        result = self._collection.insert_one(doc)

        # Optionally, update the model's object_id field
        if hasattr(model, "object_id"):
            model.object_id = result.inserted_id

        return model

    async def create_async(self, model: TModel) -> TModel:
        """
        Asynchronously create a new model instance and add it to the MongoDB collection.
        :param model: The model instance to create
        :return: The created model instance (with _id/object_id if generated by Mongo)
        """
        self._set_id(model)
        self._set_or_update_timestamps(model)
        doc = model.model_dump(by_alias=True, exclude_unset=True)

        result = await self._collection_async.insert_one(doc)

        # Optionally, update the model's object_id field
        if hasattr(model, "object_id"):
            model.object_id = result.inserted_id

        return model

    def update(self, model: TModel) -> TModel:
        """
        Update an existing model instance in the MongoDB collection.
        :param model: The model instance to update
        :return: The updated model instance
        """
        if model.id is None:
            raise ValueError(
                f"The id of the existing model ({self._model.__name__}) is required for update action"
            )

        # Check if the model exists
        existing = self.get_by_id(model.id)
        if not existing:
            raise ValueError(
                f"Model of type {self._model.__name__} with id: {model.id} not found"
            )

        # Prepare update doc (exclude unset, avoid overwriting _id unless you want to)
        update_doc = self._prepare_update_doc(model)

        result = self._collection.update_one({"id": model.id}, {"$set": update_doc})
        if result.matched_count == 0:
            raise ValueError(
                f"Model of type {self._model.__name__} with id: {model.id} not found for update"
            )

        return model

    async def update_async(self, model: TModel) -> TModel:
        """
        Asynchronously update an existing model instance in the MongoDB collection.
        :param model: The model instance to update
        :return: The updated model instance
        """
        if model.id is None:
            raise ValueError(
                f"The id of the existing model ({self._model.__name__}) is required for update action"
            )

        existing = await self.get_by_id_async(model.id)
        if not existing:
            raise ValueError(
                f"Model of type {self._model.__name__} with id: {model.id} not found"
            )

        update_doc = self._prepare_update_doc(model)

        result = await self._collection_async.update_one(
            {"id": model.id}, {"$set": update_doc}
        )
        if result.matched_count == 0:
            raise ValueError(
                f"Model of type {self._model.__name__} with id: {model.id} not found for update"
            )

        return model

    def delete(self, id: TId) -> None:
        """
        Delete a single object as specified by its primary key.
        :param id: The model's primary key (e.g., 'id')
        :return: None
        """
        result = self._collection.delete_one({"id": id})
        if result.deleted_count == 0:
            raise ValueError(f"Model with id {id} not found for delete")

    async def delete_async(self, id: TId) -> None:
        """
        Asynchronously delete a single object as specified by its primary key.
        :param id: The model's primary key (e.g., 'id')
        :return: None
        """
        result = await self._collection_async.delete_one({"id": id})
        if result.deleted_count == 0:
            raise ValueError(f"Model with id {id} not found for delete")

    ############ PRIVATE METHODS ############
    def _order_skip_limit(self, cursor, order_by, skip, limit, total):
        # 5. Add ordering, if provided
        if order_by:
            sort_spec = []
            for field in order_by:
                direction = 1  # Ascending
                if field.startswith("-"):
                    field = field[1:]
                    direction = -1
                sort_spec.append((field, direction))
            if sort_spec:
                cursor = cursor.sort(sort_spec)
        # 6. Apply skip/limit
        skip_val = skip if skip is not None else 0
        if skip_val:
            cursor = cursor.skip(skip_val)
        limit_val = limit if limit is not None else total
        if limit_val:
            cursor = cursor.limit(limit_val)
        return cursor, skip_val, limit_val

    def _set_or_update_timestamps(self, model: TModel):
        """
        Set the created_on and updated_on timestamps for the model.
        This method should be called before inserting or updating the model.
        """
        if hasattr(model, "created_on") and model.created_on is None:
            model.created_on = utc_now_time_aware()

        if hasattr(model, "updated_on"):
            model.updated_on = utc_now_time_aware()

    def _set_id(self, model: TModel):
        """
        Set the id for the model if it is not already set.
        This method should be called before inserting the model.
        """
        if hasattr(model, "id") and model.id is None:
            model.id = self.generate_id()

    def _prepare_update_doc(self, model: TModel) -> dict:
        """
        Prepare the update document for the model.
        This method excludes unset fields and avoids overwriting _id.
        """
        self._set_or_update_timestamps(model)
        update_doc = model.model_dump(by_alias=True, exclude_unset=True)
        if "_id" in update_doc:
            update_doc.pop("_id")
        return update_doc
