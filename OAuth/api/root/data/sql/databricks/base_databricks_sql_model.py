import uuid

from sqlalchemy import Column, Uuid
from sqlalchemy.orm import declared_attr
from databricks.sqlalchemy import TIMESTAMP

from root.core.util.datetime_helpers import utc_now_time_aware
from root.core.util.string_helpers import snake_to_camel, title_to_snake
from root.data.sql.base_sql_model import BaseSqlModel


class BaseDatabricksSqlModel(BaseSqlModel[Uuid]):
    __abstract__ = True

    @classmethod
    def id_model_type(cls):
        return Uuid

    @classmethod
    def default_id(cls):
        return lambda: uuid.uuid4()

    @declared_attr
    def __tablename__(cls):
        return title_to_snake(cls.__name__)

    created_on = Column(TIMESTAMP, default=utc_now_time_aware)
    updated_on = Column(TIMESTAMP, default=utc_now_time_aware)

    @property
    def timestamp(self):  # alias
        return self.created_on

    class Config:
        alias_generator = snake_to_camel
