"""
Enhanced base authentication service with common functionality.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Union
from fastapi import Response
from root.auth.models.user import User
from root.auth.utils.security import SecurityUtils
from root.auth.config import config
from root.auth.exceptions.auth_exceptions import ValidationError
import json
import logging

# Configure logging
logger = logging.getLogger(__name__)


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

    def _get_security_utils(self) -> SecurityUtils:
        """Get the SecurityUtils instance for use in child classes."""
        return self._security_utils

    def _format_auth_response(
        self,
        user: User,
        access_token: str,
        refresh_token: str,
        additional_data: Optional[Dict[str, Any]] = None,
        set_cookies: bool = False,
    ) -> Union[Dict[str, Any], Response]:
        """
        Format authentication response with optional cookie support.
        """
        if not isinstance(access_token, str) or not access_token:
            raise ValidationError("Access token must be a non-empty string")
        if not isinstance(refresh_token, str) or not refresh_token:
            raise ValidationError("Refresh token must be a non-empty string")

        try:
            # Handle different user model types (Pydantic or custom)
            user_data = user.dict() if hasattr(user, "dict") else vars(user)
            # Remove sensitive fields from user data
            sensitive_fields = ["hashed_password", "password"]
            user_data = {
                k: v for k, v in user_data.items() if k not in sensitive_fields
            }

            response_data = {
                "user": user_data,
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer",
            }

            if additional_data:
                if not isinstance(additional_data, dict):
                    raise ValidationError("Additional data must be a dictionary")
                response_data.update(additional_data)

            if set_cookies:
                response = Response(
                    content=json.dumps(response_data, default=str),
                    media_type="application/json",
                )
                response.set_cookie(
                    key="access_token",
                    value=access_token,
                    max_age=config.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                    httponly=True,
                    secure=config.COOKIE_SECURE,
                    samesite=config.COOKIE_SAMESITE,
                    domain=config.COOKIE_DOMAIN,
                    path=config.COOKIE_PATH,
                )
                response.set_cookie(
                    key="refresh_token",
                    value=refresh_token,
                    max_age=config.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
                    httponly=True,
                    secure=config.COOKIE_SECURE,
                    samesite=config.COOKIE_SAMESITE,
                    domain=config.COOKIE_DOMAIN,
                    path=config.COOKIE_PATH,
                )
                return response

            return response_data

        except Exception as e:
            logger.error(f"Failed to format auth response: {str(e)}", exc_info=True)
            raise ValidationError(f"Failed to format auth response: {str(e)}") from e

    def _create_logout_response(self, success: bool = True) -> Response:
        """Create response that clears authentication cookies."""
        response = Response(
            content=json.dumps({"success": success}, default=str),
            media_type="application/json",
        )
        return self._clear_auth_cookies(response)

    def _validate_credentials(self, credentials: Dict[str, Any]) -> None:
        """
        Validate authentication credentials.
        Override in child classes for specific validation.
        """
        if not isinstance(credentials, dict):
            raise ValidationError("Credentials must be a dictionary")

    def _validate_user_data(self, user_data: Dict[str, Any]) -> None:
        """
        Validate user registration data.
        Override in child classes for specific validation.
        """
        if not isinstance(user_data, dict):
            raise ValidationError("User data must be a dictionary")

    def _validate_required_fields(
        self, data: Dict[str, Any], required_fields: list[str]
    ) -> None:
        """Validate that required fields are present and non-empty."""
        if not isinstance(data, dict):
            raise ValidationError("Data must be a dictionary")
        missing_fields = [
            field
            for field in required_fields
            if not data.get(field)
            or (isinstance(data.get(field), str) and not data.get(field).strip())
        ]
        if missing_fields:
            raise ValidationError(
                f"Missing or empty required fields: {', '.join(missing_fields)}"
            )

    def _sanitize_user_data(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize user data for safe storage."""
        if not isinstance(user_data, dict):
            raise ValidationError("User data must be a dictionary")
        sensitive_fields = ["password", "confirm_password", "raw_password"]
        return {k: v for k, v in user_data.items() if k not in sensitive_fields}

    def _handle_auth_error(self, error: Exception, operation: str) -> None:
        """
        Handle authentication errors with consistent logging.
        """
        error_msg = f"Authentication error during {operation}: {str(error)}"
        logger.error(error_msg, exc_info=True)
        raise

    def _clear_auth_cookies(self, response: Response) -> Response:
        """
        Clear authentication cookies from response.
        """
        if not isinstance(response, Response):
            raise ValidationError("Response must be a FastAPI Response object")
        response.delete_cookie(
            key="access_token",
            domain=config.COOKIE_DOMAIN,
            path=config.COOKIE_PATH,
        )
        response.delete_cookie(
            key="refresh_token",
            domain=config.COOKIE_DOMAIN,
            path=config.COOKIE_PATH,
        )
        return response

    async def _clear_auth_cookies_async(self, response: Response) -> Response:
        """
        Async version of clear authentication cookies from response.
        """
        return self._clear_auth_cookies(response)

    @abstractmethod
    def authenticate(
        self, credentials: Dict[str, Any], set_cookies: bool = False
    ) -> Union[Dict[str, Any], Response]:
        """
        Authenticate a user with provided credentials.
        """
        pass

    @abstractmethod
    async def authenticate_async(
        self, credentials: Dict[str, Any], set_cookies: bool = False
    ) -> Union[Dict[str, Any], Response]:
        """Authenticate a user with provided credentials (async)."""
        pass

    @abstractmethod
    def register(self, user_data: Dict[str, Any]) -> User:
        """
        Register a new user.
        """
        pass

    @abstractmethod
    async def register_async(self, user_data: Dict[str, Any]) -> User:
        """Register a new user (async)."""
        pass

    def verify_otp(self, user_id: str, otp_code: str) -> bool:
        """
        Verify OTP code for a user (future functionality).
        """
        if not isinstance(user_id, str) or not isinstance(otp_code, str):
            raise ValidationError("User ID and OTP code must be strings")
        return False

    async def verify_otp_async(self, user_id: str, otp_code: str) -> bool:
        """
        Verify OTP code for a user (future functionality, async).
        """
        if not isinstance(user_id, str) or not isinstance(otp_code, str):
            raise ValidationError("User ID and OTP code must be strings")
        return False

    def generate_otp_secret(self, user_id: str) -> str:
        """
        Generate OTP secret for a user (future functionality).
        """
        if not isinstance(user_id, str) or not user_id:
            raise ValidationError("User ID must be a non-empty string")
        return self._get_security_utils().generate_otp_secret()

    def generate_otp_qr_uri(self, user_email: str, otp_secret: str) -> str:
        """
        Generate OTP QR code URI (future functionality).
        """
        if not isinstance(user_email, str) or not isinstance(otp_secret, str):
            raise ValidationError("User email and OTP secret must be strings")
        return self._get_security_utils().generate_totp_uri(user_email, otp_secret)
