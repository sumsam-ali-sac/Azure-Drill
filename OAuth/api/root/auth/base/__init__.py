"""
Base classes for the authentication service.
"""

from .mongo_base import BaseMongoModel, BaseMongoRepository, BaseMongoManager
from .auth_base import BaseAuthService

__all__ = [
    "BaseMongoModel", 
    "BaseMongoRepository", 
    "BaseMongoManager",
    "BaseAuthService"
]
