"""
OTP manager for business logic operations.
"""

from typing import Optional, List
from auth_service.base.mongo_base import BaseMongoManager
from auth_service.models.otp_code import OTPCode
from auth_service.repositories.otp_repository import OTPRepository

class OTPManager(BaseMongoManager[str, OTPCode]):
    """
    OTP manager for orchestrating OTP business logic.
    """
    
    def __init__(self, repository: OTPRepository):
        """Initialize OTP manager with repository."""
        super().__init__(repository)
        self._otp_repository = repository
    
    def get_user_otp(self, user_id: str) -> Optional[OTPCode]:
        """Get OTP configuration for user."""
        return self._otp_repository.find_by_user_id(user_id)
    
    async def get_user_otp_async(self, user_id: str) -> Optional[OTPCode]:
        """Get OTP configuration for user (async)."""
        return await self._otp_repository.find_by_user_id_async(user_id)
    
    def get_active_user_otp(self, user_id: str) -> Optional[OTPCode]:
        """Get active OTP configuration for user."""
        return self._otp_repository.find_active_by_user_id(user_id)
    
    async def get_active_user_otp_async(self, user_id: str) -> Optional[OTPCode]:
        """Get active OTP configuration for user (async)."""
        return await self._otp_repository.find_active_by_user_id_async(user_id)
    
    def enable_otp_for_user(self, user_id: str, secret: str, backup_codes: List[str]) -> OTPCode:
        """Enable OTP for a user."""
        # Disable any existing OTP first
        existing = self.get_user_otp(user_id)
        if existing:
            existing.is_active = False
            self.update(existing)
        
        # Create new OTP configuration
        otp_code = OTPCode(
            user_id=user_id,
            secret=secret,
            backup_codes=backup_codes,
            is_active=True,
            is_verified=False
        )
        
        return self.create(otp_code)
    
    async def enable_otp_for_user_async(self, user_id: str, secret: str, backup_codes: List[str]) -> OTPCode:
        """Enable OTP for a user (async)."""
        # Disable any existing OTP first
        existing = await self.get_user_otp_async(user_id)
        if existing:
            existing.is_active = False
            await self.update_async(existing)
        
        # Create new OTP configuration
        otp_code = OTPCode(
            user_id=user_id,
            secret=secret,
            backup_codes=backup_codes,
            is_active=True,
            is_verified=False
        )
        
        return await self.create_async(otp_code)
    
    def disable_otp_for_user(self, user_id: str) -> bool:
        """Disable OTP for a user."""
        otp_code = self.get_active_user_otp(user_id)
        if otp_code:
            otp_code.is_active = False
            self.update(otp_code)
            return True
        return False
    
    async def disable_otp_for_user_async(self, user_id: str) -> bool:
        """Disable OTP for a user (async)."""
        otp_code = await self.get_active_user_otp_async(user_id)
        if otp_code:
            otp_code.is_active = False
            await self.update_async(otp_code)
            return True
        return False
