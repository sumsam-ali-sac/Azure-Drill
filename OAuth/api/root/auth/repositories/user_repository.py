"""
User repository for MongoDB operations.
"""

import uuid
from typing import Optional, List
from auth_service.base.mongo_base import BaseMongoRepository
from auth_service.models.user import User

class UserRepository(BaseMongoRepository[User, str]):
    """
    User repository implementing MongoDB operations.
    
    Inherits from BaseMongoRepository[User, str] and implements:
    - get_collection_name(): Returns collection name
    - _model: Returns the User model class
    - generate_id(): Generates UUID string for new users
    """
    
    def get_collection_name(self) -> str:
        """Return the MongoDB collection name for users."""
        return "users"
    
    @property
    def _model(self) -> type[User]:
        """Return the User model class."""
        return User
    
    def generate_id(self) -> str:
        """Generate a new UUID string for user ID."""
        return str(uuid.uuid4())
    
    def find_by_email(self, email: str) -> Optional[User]:
        """Find a user by email address."""
        results = self.find_by_query({"email": email}, limit=1)
        return results[0] if results else None
    
    async def find_by_email_async(self, email: str) -> Optional[User]:
        """Find a user by email address (async)."""
        results = await self.find_by_query_async({"email": email}, limit=1)
        return results[0] if results else None
    
    def find_by_social_id(self, provider: str, provider_user_id: str) -> Optional[User]:
        """Find a user by social provider ID."""
        query = {f"social_ids.{provider}": provider_user_id}
        results = self.find_by_query(query, limit=1)
        return results[0] if results else None
    
    async def find_by_social_id_async(self, provider: str, provider_user_id: str) -> Optional[User]:
        """Find a user by social provider ID (async)."""
        query = {f"social_ids.{provider}": provider_user_id}
        results = await self.find_by_query_async(query, limit=1)
        return results[0] if results else None
    
    def get_active_users(self, limit: int = 100, skip: int = 0) -> List[User]:
        """Get active users with pagination."""
        return self.find_by_query({"is_active": True}, limit, skip)
    
    async def get_active_users_async(self, limit: int = 100, skip: int = 0) -> List[User]:
        """Get active users with pagination (async)."""
        return await self.find_by_query_async({"is_active": True}, limit, skip)
