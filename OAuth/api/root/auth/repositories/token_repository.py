"""
Token repository for MongoDB operations.
"""

import uuid
from datetime import datetime
from typing import Optional, List
from root.data.nosql.mongo.base_mongo_repository import BaseMongoRepository
from auth_service.models.token import Token, TokenType

class TokenRepository(BaseMongoRepository[Token, str]):
    """
    Token repository implementing MongoDB operations.
    
    Inherits from BaseMongoRepository[Token, str] and implements:
    - get_collection_name(): Returns collection name
    - _model: Returns the Token model class
    - generate_id(): Generates UUID string for new tokens
    """
    
    def get_collection_name(self) -> str:
        """Return the MongoDB collection name for tokens."""
        return "tokens"
    
    @property
    def _model(self) -> type[Token]:
        """Return the Token model class."""
        return Token
    
    def generate_id(self) -> str:
        """Generate a new UUID string for token ID."""
        return str(uuid.uuid4())
    
    def find_by_token(self, token_string: str) -> Optional[Token]:
        """Find a token by token string."""
        try:
            collection = self.get_collection()
            token_data = collection.find_one({"token": token_string})
            if token_data:
                return Token(**token_data)
            return None
        except Exception as e:
            # Log error in production
            print(f"Error finding token: {e}")
            return None
    
    async def find_by_token_async(self, token_string: str) -> Optional[Token]:
        """Find a token by token string (async)."""
        try:
            collection = await self.get_collection_async()
            token_data = await collection.find_one({"token": token_string})
            if token_data:
                return Token(**token_data)
            return None
        except Exception as e:
            # Log error in production
            print(f"Error finding token (async): {e}")
            return None
    
    def find_by_user_id(self, user_id: str, token_type: Optional[TokenType] = None) -> List[Token]:
        """Find tokens by user ID, optionally filtered by type."""
        try:
            collection = self.get_collection()
            query = {"user_id": user_id}
            if token_type:
                query["type"] = token_type
            
            cursor = collection.find(query)
            return [Token(**token_data) for token_data in cursor]
        except Exception as e:
            # Log error in production
            print(f"Error finding tokens by user ID: {e}")
            return []
    
    async def find_by_user_id_async(self, user_id: str, token_type: Optional[TokenType] = None) -> List[Token]:
        """Find tokens by user ID, optionally filtered by type (async)."""
        try:
            collection = await self.get_collection_async()
            query = {"user_id": user_id}
            if token_type:
                query["type"] = token_type
            
            cursor = collection.find(query)
            tokens = []
            async for token_data in cursor:
                tokens.append(Token(**token_data))
            return tokens
        except Exception as e:
            # Log error in production
            print(f"Error finding tokens by user ID (async): {e}")
            return []
    
    def revoke_token(self, token_string: str) -> bool:
        """Revoke a token by setting is_revoked to True."""
        try:
            collection = self.get_collection()
            result = collection.update_one(
                {"token": token_string},
                {"$set": {"is_revoked": True, "updated_on": datetime.utcnow()}}
            )
            return result.modified_count > 0
        except Exception as e:
            # Log error in production
            print(f"Error revoking token: {e}")
            return False
    
    async def revoke_token_async(self, token_string: str) -> bool:
        """Revoke a token by setting is_revoked to True (async)."""
        try:
            collection = await self.get_collection_async()
            result = await collection.update_one(
                {"token": token_string},
                {"$set": {"is_revoked": True, "updated_on": datetime.utcnow()}}
            )
            return result.modified_count > 0
        except Exception as e:
            # Log error in production
            print(f"Error revoking token (async): {e}")
            return False
    
    def revoke_user_tokens(self, user_id: str, token_type: Optional[TokenType] = None) -> int:
        """Revoke all tokens for a user, optionally filtered by type."""
        try:
            collection = self.get_collection()
            query = {"user_id": user_id, "is_revoked": False}
            if token_type:
                query["type"] = token_type
            
            result = collection.update_many(
                query,
                {"$set": {"is_revoked": True, "updated_on": datetime.utcnow()}}
            )
            return result.modified_count
        except Exception as e:
            # Log error in production
            print(f"Error revoking user tokens: {e}")
            return 0
    
    async def revoke_user_tokens_async(self, user_id: str, token_type: Optional[TokenType] = None) -> int:
        """Revoke all tokens for a user, optionally filtered by type (async)."""
        try:
            collection = await self.get_collection_async()
            query = {"user_id": user_id, "is_revoked": False}
            if token_type:
                query["type"] = token_type
            
            result = await collection.update_many(
                query,
                {"$set": {"is_revoked": True, "updated_on": datetime.utcnow()}}
            )
            return result.modified_count
        except Exception as e:
            # Log error in production
            print(f"Error revoking user tokens (async): {e}")
            return 0
    
    def cleanup_expired_tokens(self) -> int:
        """Remove expired tokens from the database."""
        try:
            collection = self.get_collection()
            result = collection.delete_many({"expiry": {"$lt": datetime.utcnow()}})
            return result.deleted_count
        except Exception as e:
            # Log error in production
            print(f"Error cleaning up expired tokens: {e}")
            return 0
    
    async def cleanup_expired_tokens_async(self) -> int:
        """Remove expired tokens from the database (async)."""
        try:
            collection = await self.get_collection_async()
            result = await collection.delete_many({"expiry": {"$lt": datetime.utcnow()}})
            return result.deleted_count
        except Exception as e:
            # Log error in production
            print(f"Error cleaning up expired tokens (async): {e}")
            return 0
