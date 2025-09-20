"""
OTP repository for MongoDB operations.
"""

import uuid
from typing import Optional, List
from auth_service.base.mongo_base import BaseMongoRepository
from auth_service.models.otp_code import OTPCode

class OTPRepository(BaseMongoRepository[OTPCode, str]):
    """
    OTP repository implementing MongoDB operations.
    """
    
    def get_collection_name(self) -> str:
        """Return the MongoDB collection name for OTP codes."""
        return "otp_codes"
    
    @property
    def _model(self) -> type[OTPCode]:
        """Return the OTPCode model class."""
        return OTPCode
    
    def generate_id(self) -> str:
        """Generate a new UUID string for OTP code ID."""
        return str(uuid.uuid4())
    
    def find_by_user_id(self, user_id: str) -> Optional[OTPCode]:
        """Find OTP code by user ID."""
        results = self.find_by_query({"user_id": user_id}, limit=1)
        return results[0] if results else None
    
    async def find_by_user_id_async(self, user_id: str) -> Optional[OTPCode]:
        """Find OTP code by user ID (async)."""
        results = await self.find_by_query_async({"user_id": user_id}, limit=1)
        return results[0] if results else None
    
    def find_active_by_user_id(self, user_id: str) -> Optional[OTPCode]:
        """Find active OTP code by user ID."""
        query = {"user_id": user_id, "is_active": True}
        results = self.find_by_query(query, limit=1)
        return results[0] if results else None
    
    async def find_active_by_user_id_async(self, user_id: str) -> Optional[OTPCode]:
        """Find active OTP code by user ID (async)."""
        query = {"user_id": user_id, "is_active": True}
        results = await self.find_by_query_async(query, limit=1)
        return results[0] if results else None
