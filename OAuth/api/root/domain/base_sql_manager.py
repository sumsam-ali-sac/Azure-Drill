from abc import ABC
from typing import TypeVar

from root.data.sql.base_sql_model import BaseSqlModel
from root.domain.base_manager import BaseManager

TModel = TypeVar("TModel", bound=BaseSqlModel)


class BaseSqlManager(BaseManager[TModel], ABC):
    pass
