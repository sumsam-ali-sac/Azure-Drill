"""
User manager for orchestrating user operations.
"""

from typing import Optional, List
from auth_service.base.mongo_base import BaseMongoManager
from auth_service.models.user import User
from auth_service.repositories.user_repository import UserRepository
from auth_service.exceptions.auth_exceptions import UserNotFoundError, UserAlreadyExistsError

class UserManager(BaseMongoManager[str, User]):
    """
    User manager for orchestrating user operations.
    
    Inherits from BaseMongoManager[str, User] and wraps UserRepository
    for business logic orchestration.
    """
    
    def __init__(self, user_repository: UserRepository):
        """Initialize with user repository."""
        super().__init__(user_repository)
        self._user_repository = user_repository
    
    def create_user(self, email: str, hashed_password: Optional[str] = None, 
                   first_name: Optional[str] = None, last_name: Optional[str] = None,
                   social_ids: Optional[dict] = None) -> User:
        """
        Create a new user.
        
        Args:
            email: User's email address
            hashed_password: Hashed password (for email/password auth)
            first_name: User's first name
            last_name: User's last name
            social_ids: Social provider IDs
            
        Returns:
            Created User object
            
        Raises:
            UserAlreadyExistsError: If user with email already exists
        """
        # Check if user already exists
        existing_user = self._user_repository.find_by_email(email)
        if existing_user:
            raise UserAlreadyExistsError(f"User with email {email} already exists")
        
        # Create new user
        user_data = {
            "email": email,
            "hashed_password": hashed_password,
            "first_name": first_name,
            "last_name": last_name,
            "social_ids": social_ids or {},
            "is_active": True
        }
        
        user = User(**user_data)
        return self.create(user)
    
    async def create_user_async(self, email: str, hashed_password: Optional[str] = None,
                               first_name: Optional[str] = None, last_name: Optional[str] = None,
                               social_ids: Optional[dict] = None) -> User:
        """Create a new user (async)."""
        # Check if user already exists
        existing_user = await self._user_repository.find_by_email_async(email)
        if existing_user:
            raise UserAlreadyExistsError(f"User with email {email} already exists")
        
        # Create new user
        user_data = {
            "email": email,
            "hashed_password": hashed_password,
            "first_name": first_name,
            "last_name": last_name,
            "social_ids": social_ids or {},
            "is_active": True
        }
        
        user = User(**user_data)
        return await self.create_async(user)
    
    def get_user_by_email(self, email: str) -> User:
        """
        Get user by email address.
        
        Args:
            email: User's email address
            
        Returns:
            User object
            
        Raises:
            UserNotFoundError: If user not found
        """
        user = self._user_repository.find_by_email(email)
        if not user:
            raise UserNotFoundError(f"User with email {email} not found")
        return user
    
    async def get_user_by_email_async(self, email: str) -> User:
        """Get user by email address (async)."""
        user = await self._user_repository.find_by_email_async(email)
        if not user:
            raise UserNotFoundError(f"User with email {email} not found")
        return user
    
    def get_user_by_social_id(self, provider: str, provider_user_id: str) -> Optional[User]:
        """Get user by social provider ID."""
        return self._user_repository.find_by_social_id(provider, provider_user_id)
    
    async def get_user_by_social_id_async(self, provider: str, provider_user_id: str) -> Optional[User]:
        """Get user by social provider ID (async)."""
        return await self._user_repository.find_by_social_id_async(provider, provider_user_id)
    
    def update_user(self, user: User) -> User:
        """Update user information."""
        return self.update(user)
    
    async def update_user_async(self, user: User) -> User:
        """Update user information (async)."""
        return await self.update_async(user)
    
    def deactivate_user(self, user_id: str) -> User:
        """Deactivate a user account."""
        user = self.get_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User with ID {user_id} not found")
        
        user.is_active = False
        return self.update(user)
    
    async def deactivate_user_async(self, user_id: str) -> User:
        """Deactivate a user account (async)."""
        user = await self.get_by_id_async(user_id)
        if not user:
            raise UserNotFoundError(f"User with ID {user_id} not found")
        
        user.is_active = False
        return await self.update_async(user)
    
    def activate_user(self, user_id: str) -> User:
        """Activate a user account."""
        user = self.get_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User with ID {user_id} not found")
        
        user.is_active = True
        return self.update(user)
    
    async def activate_user_async(self, user_id: str) -> User:
        """Activate a user account (async)."""
        user = await self.get_by_id_async(user_id)
        if not user:
            raise UserNotFoundError(f"User with ID {user_id} not found")
        
        user.is_active = True
        return await self.update_async(user)
    
    def link_social_provider(self, user_id: str, provider: str, provider_user_id: str) -> User:
        """Link a social provider to a user account."""
        user = self.get_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User with ID {user_id} not found")
        
        user.add_social_provider(provider, provider_user_id)
        return self.update(user)
    
    async def link_social_provider_async(self, user_id: str, provider: str, provider_user_id: str) -> User:
        """Link a social provider to a user account (async)."""
        user = await self.get_by_id_async(user_id)
        if not user:
            raise UserNotFoundError(f"User with ID {user_id} not found")
        
        user.add_social_provider(provider, provider_user_id)
        return await self.update_async(user)
    
    def unlink_social_provider(self, user_id: str, provider: str) -> User:
        """Unlink a social provider from a user account."""
        user = self.get_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User with ID {user_id} not found")
        
        user.remove_social_provider(provider)
        return self.update(user)
    
    async def unlink_social_provider_async(self, user_id: str, provider: str) -> User:
        """Unlink a social provider from a user account (async)."""
        user = await self.get_by_id_async(user_id)
        if not user:
            raise UserNotFoundError(f"User with ID {user_id} not found")
        
        user.remove_social_provider(provider)
        return await self.update_async(user)
    
    # Future OTP support methods
    def setup_otp(self, user_id: str, otp_secret: str) -> User:
        """Set up OTP for a user (future functionality)."""
        user = self.get_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User with ID {user_id} not found")
        
        user.otp_secret = otp_secret
        return self.update(user)
    
    async def setup_otp_async(self, user_id: str, otp_secret: str) -> User:
        """Set up OTP for a user (future functionality, async)."""
        user = await self.get_by_id_async(user_id)
        if not user:
            raise UserNotFoundError(f"User with ID {user_id} not found")
        
        user.otp_secret = otp_secret
        return await self.update_async(user)
    
    def verify_otp(self, user_id: str, otp_code: str) -> bool:
        """Verify OTP code for a user (future functionality)."""
        # This will be implemented when OTP functionality is added
        # Will use pyotp library to verify TOTP codes
        user = self.get_by_id(user_id)
        if not user or not user.otp_secret:
            return False
        
        # TODO: Implement OTP verification using pyotp
        # import pyotp
        # totp = pyotp.TOTP(user.otp_secret)
        # return totp.verify(otp_code)
        
        return False  # Placeholder
    
    async def verify_otp_async(self, user_id: str, otp_code: str) -> bool:
        """Verify OTP code for a user (future functionality, async)."""
        # This will be implemented when OTP functionality is added
        user = await self.get_by_id_async(user_id)
        if not user or not user.otp_secret:
            return False
        
        # TODO: Implement OTP verification using pyotp
        return False  # Placeholder
