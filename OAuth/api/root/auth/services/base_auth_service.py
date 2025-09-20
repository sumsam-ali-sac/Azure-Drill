"""
Enhanced base authentication service with common functionality.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Union
from fastapi import Response
from auth_service.models.user import User
from auth_service.utils.security import SecurityUtils
from auth_service.config import config
import json

class BaseAuthService(ABC):
    """
    Abstract base class for authentication services with comprehensive common functionality.
    
    Provides:
    - Abstract methods for authentication and registration
    - Common cookie handling with secure defaults
    - Response formatting utilities
    - Input validation helpers
    - Error handling framework
    - OTP support framework for future expansion
    """
    
    def __init__(self):
        """Initialize base service with common utilities."""
        self._security_utils = SecurityUtils()
    
    def _format_response(self, user: User, tokens: Dict[str, str], set_cookies: bool = False) -> Union[Dict[str, Any], Response]:
        """
        Format authentication response with optional cookie support.
        
        Args:
            user: Authenticated user
            tokens: JWT tokens dict
            set_cookies: Whether to set HTTP-only cookies
            
        Returns:
            Response dict or FastAPI Response with cookies
        """
        response_data = {
            "user": user.dict(),
            "access_token": tokens["access_token"],
            "refresh_token": tokens["refresh_token"],
            "token_type": "bearer"
        }
        
        if set_cookies:
            response = Response(
                content=json.dumps(response_data, default=str),
                media_type="application/json"
            )
            
            # Set HTTP-only cookies with secure defaults
            response.set_cookie(
                key="access_token",
                value=tokens["access_token"],
                max_age=config.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                httponly=True,
                secure=config.COOKIE_SECURE,
                samesite=config.COOKIE_SAMESITE,
                domain=config.COOKIE_DOMAIN,
                path=config.COOKIE_PATH
            )
            
            response.set_cookie(
                key="refresh_token",
                value=tokens["refresh_token"],
                max_age=config.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
                httponly=True,
                secure=config.COOKIE_SECURE,
                samesite=config.COOKIE_SAMESITE,
                domain=config.COOKIE_DOMAIN,
                path=config.COOKIE_PATH
            )
            
            return response
        
        return response_data
    
    def _create_cookie_response(self, response_dict: Dict[str, Any], access_token: str, refresh_token: str) -> Response:
        """Create response with authentication cookies."""
        response = Response(
            content=json.dumps(response_dict, default=str),
            media_type="application/json"
        )
        
        # Set access token cookie
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            secure=config.COOKIE_SECURE,
            samesite=config.COOKIE_SAMESITE,
            max_age=config.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            domain=config.COOKIE_DOMAIN,
            path=config.COOKIE_PATH
        )
        
        # Set refresh token cookie
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            secure=config.COOKIE_SECURE,
            samesite=config.COOKIE_SAMESITE,
            max_age=config.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
            domain=config.COOKIE_DOMAIN,
            path=config.COOKIE_PATH
        )
        
        return response
    
    def _create_logout_response(self, success: bool = True) -> Response:
        """Create response that clears authentication cookies."""
        response = Response(
            content=json.dumps({"success": success}),
            media_type="application/json"
        )
        
        # Clear access token cookie
        response.delete_cookie(
            key="access_token",
            domain=config.COOKIE_DOMAIN,
            path=config.COOKIE_PATH
        )
        
        # Clear refresh token cookie
        response.delete_cookie(
            key="refresh_token",
            domain=config.COOKIE_DOMAIN,
            path=config.COOKIE_PATH
        )
        
        return response
    
    def _validate_credentials(self, credentials: Dict[str, Any]) -> None:
        """
        Validate authentication credentials.
        Override in child classes for specific validation.
        
        Args:
            credentials: Credentials to validate
            
        Raises:
            ValidationError: If credentials are invalid
        """
        pass
    
    def _validate_user_data(self, user_data: Dict[str, Any]) -> None:
        """
        Validate user registration data.
        Override in child classes for specific validation.
        
        Args:
            user_data: User data to validate
            
        Raises:
            ValidationError: If user data is invalid
        """
        pass
    
    def _validate_required_fields(self, data: Dict[str, Any], required_fields: list[str]) -> None:
        """Validate that required fields are present."""
        from auth_service.exceptions.auth_exceptions import ValidationError
        
        missing_fields = [field for field in required_fields if not data.get(field)]
        if missing_fields:
            raise ValidationError(f"Missing required fields: {', '.join(missing_fields)}")
    
    def _sanitize_user_data(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize user data for safe storage."""
        # Remove sensitive fields that shouldn't be stored
        sensitive_fields = ['password', 'confirm_password', 'raw_password']
        return {k: v for k, v in user_data.items() if k not in sensitive_fields}
    
    def _handle_auth_error(self, error: Exception, operation: str) -> None:
        """
        Handle authentication errors with consistent logging.
        
        Args:
            error: The exception that occurred
            operation: The operation that failed
        """
        error_msg = f"Authentication error during {operation}: {str(error)}"
        print(f"[AUTH_ERROR] {error_msg}")
        # In production, use proper logging
        # logger.error(error_msg, exc_info=True)
        
        # Re-raise the error for proper handling
        raise error
    
    def _format_auth_response(self, user: User, access_token: str, refresh_token: str, 
                             additional_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Format standard authentication response."""
        response = {
            "user": user.dict(),
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer"
        }
        
        if additional_data:
            response.update(additional_data)
        
        return response
    
    def _clear_auth_cookies(self, response: Response) -> Response:
        """
        Clear authentication cookies from response.
        
        Args:
            response: FastAPI Response object
            
        Returns:
            Response with cleared cookies
        """
        response.delete_cookie(key="access_token")
        response.delete_cookie(key="refresh_token")
        return response
    
    @abstractmethod
    def authenticate(self, credentials: Dict[str, Any], set_cookies: bool = False) -> Union[Dict[str, Any], Response]:
        """
        Authenticate a user with provided credentials.
        
        Args:
            credentials: Authentication credentials (varies by service)
            set_cookies: Whether to set HTTP-only cookies
            
        Returns:
            Authentication result with user and tokens
        """
        pass
    
    @abstractmethod
    async def authenticate_async(self, credentials: Dict[str, Any], set_cookies: bool = False) -> Union[Dict[str, Any], Response]:
        """Authenticate a user with provided credentials (async)."""
        pass
    
    @abstractmethod
    def register(self, user_data: Dict[str, Any]) -> User:
        """
        Register a new user.
        
        Args:
            user_data: User registration data
            
        Returns:
            Created User object
        """
        pass
    
    @abstractmethod
    async def register_async(self, user_data: Dict[str, Any]) -> User:
        """Register a new user (async)."""
        pass
    
    # Future OTP support framework
    def verify_otp(self, user_id: str, otp_code: str) -> bool:
        """
        Verify OTP code for a user (future functionality).
        
        Args:
            user_id: ID of the user
            otp_code: OTP code to verify
            
        Returns:
            True if OTP is valid, False otherwise
        """
        # Default implementation - to be overridden by services that support OTP
        return False
    
    async def verify_otp_async(self, user_id: str, otp_code: str) -> bool:
        """Verify OTP code for a user (future functionality, async)."""
        # Default implementation - to be overridden by services that support OTP
        return False
    
    def generate_otp_secret(self, user_id: str) -> str:
        """Generate OTP secret for a user (future functionality)."""
        return self._security_utils.generate_otp_secret()
    
    def generate_otp_qr_uri(self, user_email: str, otp_secret: str) -> str:
        """Generate OTP QR code URI (future functionality)."""
        return self._security_utils.generate_totp_uri(user_email, otp_secret)
