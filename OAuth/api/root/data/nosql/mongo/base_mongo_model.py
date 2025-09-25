from datetime import datetime
from typing import Optional, TypeVar, Generic, Union
from pydantic import BaseModel, Field
from bson import ObjectId

TId = TypeVar("TId", bound=Union[str, int, ObjectId])


class BaseMongoModel(BaseModel, Generic[TId]):
    id: Optional[TId] = Field(default=None)
    model_type: str = Field(default=None)
    created_on: Optional[datetime] = None
    updated_on: Optional[datetime] = None

    def __init__(self, **kwargs):
        kwargs.setdefault("model_type", self.__class__.__name__)
        super().__init__(**kwargs)

    class Config:
        validate_by_name = True
        arbitrary_types_allowed = True
