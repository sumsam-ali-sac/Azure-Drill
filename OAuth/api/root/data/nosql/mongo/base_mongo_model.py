from datetime import datetime
from typing import Optional, TypeVar, Generic

from pydantic import BaseModel, Field

TId = TypeVar('TId', bound=any)

class BaseMongoModel(BaseModel, Generic[TId]):
    id: Optional[TId] = Field(default=None)
    model_type: str = Field(default=None)
    created_on: Optional[datetime] = None
    updated_on: Optional[datetime] = None

    def __init__(self, **kwargs):
        kwargs.setdefault("model_type", self.__class__.__name__)
        super().__init__(**kwargs)

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True

