"""
Authentication service for email/password authentication.
"""

from typing import Dict, Any, Optional, Union
from auth.services.base_auth_service import BaseAuthService
from auth.models.user import User
from auth.managers.user_manager import UserManager
from auth.managers.token_manager import TokenManager
from auth.utils.security import SecurityUtils
from auth.utils.validators import EmailValidator, PasswordValidator
from auth.exceptions.auth_exceptions import (
    InvalidCredentialsError,
    UserAlreadyExistsError,
    ValidationError,
)
from fastapi import Response


class AuthService(BaseAuthService):
    """
    Authentication service for email/password authentication.

    Handles user registration, login, password reset, and other
    email/password authentication flows.
    """

    def __init__(
        self,
        user_manager: UserManager,
        token_manager: TokenManager,
        security_utils: SecurityUtils,
    ):
        """Initialize with required managers and utilities."""
        super().__init__()
        self._user_manager = user_manager
        self._token_manager = token_manager
        self._security_utils = security_utils
        self._email_validator = EmailValidator()
        self._password_validator = PasswordValidator()

    def authenticate(
        self, credentials: Dict[str, Any], set_cookies: bool = False
    ) -> Union[Dict[str, Any], Response]:
        """
        Authenticate user with email and password.

        Args:
            credentials: Dict with 'email' and 'password' keys
            set_cookies: Whether to set HTTP cookies for tokens

        Returns:
            Dict with user info and tokens, or Response object if set_cookies=True

        Raises:
            InvalidCredentialsError: If credentials are invalid
            ValidationError: If input validation fails
        """
        self._validate_required_fields(credentials, ["email", "password"])

        email = credentials.get("email")
        password = credentials.get("password")

        # Validate email format
        if not self._email_validator.validate(email):
            raise ValidationError("Invalid email format")

        try:
            # Get user by email
            user = self._user_manager.get_user_by_email(email)

            # Check if user is active
            if not user.is_active:
                raise InvalidCredentialsError("Account is deactivated")

            # Verify password
            if not user.hashed_password:
                raise InvalidCredentialsError(
                    "Password authentication not set up for this user"
                )

            if not self._security_utils.verify_password(password, user.hashed_password):
                raise InvalidCredentialsError("Invalid email or password")

            # Generate tokens
            tokens = self._token_manager.generate_token_pair(user.id)

            response_dict = self._format_auth_response(
                user, tokens["access"].token, tokens["refresh"].token
            )

            if set_cookies:
                return self._create_cookie_response(
                    response_dict, tokens["access"].token, tokens["refresh"].token
                )

            return response_dict

        except Exception as e:
            if isinstance(e, (InvalidCredentialsError, ValidationError)):
                raise
            self._handle_auth_error(e, "email/password authentication")
            raise InvalidCredentialsError("Authentication failed")

    async def authenticate_async(
        self, credentials: Dict[str, Any], set_cookies: bool = False
    ) -> Union[Dict[str, Any], Response]:
        """Authenticate user with email and password (async)."""
        self._validate_required_fields(credentials, ["email", "password"])

        email = credentials.get("email")
        password = credentials.get("password")

        # Validate email format
        if not self._email_validator.validate(email):
            raise ValidationError("Invalid email format")

        try:
            # Get user by email
            user = await self._user_manager.get_user_by_email_async(email)

            # Check if user is active
            if not user.is_active:
                raise InvalidCredentialsError("Account is deactivated")

            # Verify password
            if not user.hashed_password:
                raise InvalidCredentialsError(
                    "Password authentication not set up for this user"
                )

            if not self._security_utils.verify_password(password, user.hashed_password):
                raise InvalidCredentialsError("Invalid email or password")

            # Generate tokens
            tokens = await self._token_manager.generate_token_pair_async(user.id)

            response_dict = self._format_auth_response(
                user, tokens["access"].token, tokens["refresh"].token
            )

            if set_cookies:
                return self._create_cookie_response(
                    response_dict, tokens["access"].token, tokens["refresh"].token
                )

            return response_dict

        except Exception as e:
            if isinstance(e, (InvalidCredentialsError, ValidationError)):
                raise
            self._handle_auth_error(e, "email/password authentication (async)")
            raise InvalidCredentialsError("Authentication failed")

    def register(self, user_data: Dict[str, Any]) -> User:
        """
        Register a new user with email and password.

        Args:
            user_data: Dict with user registration data

        Returns:
            Created User object

        Raises:
            UserAlreadyExistsError: If user already exists
            ValidationError: If input validation fails
        """
        self._validate_required_fields(user_data, ["email", "password"])

        email = user_data.get("email")
        password = user_data.get("password")
        first_name = user_data.get("first_name")
        last_name = user_data.get("last_name")

        # Validate email
        if not self._email_validator.validate(email):
            raise ValidationError("Invalid email format")

        # Validate password
        password_validation = self._password_validator.validate(password)
        if not password_validation["is_valid"]:
            raise ValidationError(
                f"Password validation failed: {', '.join(password_validation['errors'])}"
            )

        # Hash password
        hashed_password = self._security_utils.hash_password(password)

        # Create user
        user = self._user_manager.create_user(
            email=email,
            hashed_password=hashed_password,
            first_name=first_name,
            last_name=last_name,
        )

        return user

    async def register_async(self, user_data: Dict[str, Any]) -> User:
        """Register a new user with email and password (async)."""
        self._validate_required_fields(user_data, ["email", "password"])

        email = user_data.get("email")
        password = user_data.get("password")
        first_name = user_data.get("first_name")
        last_name = user_data.get("last_name")

        # Validate email
        if not self._email_validator.validate(email):
            raise ValidationError("Invalid email format")

        # Validate password
        password_validation = self._password_validator.validate(password)
        if not password_validation["is_valid"]:
            raise ValidationError(
                f"Password validation failed: {', '.join(password_validation['errors'])}"
            )

        # Hash password
        hashed_password = self._security_utils.hash_password(password)

        # Create user
        user = await self._user_manager.create_user_async(
            email=email,
            hashed_password=hashed_password,
            first_name=first_name,
            last_name=last_name,
        )

        return user

    def change_password(
        self, user_id: str, old_password: str, new_password: str
    ) -> bool:
        """
        Change user's password.

        Args:
            user_id: ID of the user
            old_password: Current password
            new_password: New password

        Returns:
            True if password was changed successfully

        Raises:
            InvalidCredentialsError: If old password is incorrect
            ValidationError: If new password validation fails
        """
        # Get user
        user = self._user_manager.get_by_id(user_id)
        if not user:
            raise InvalidCredentialsError("User not found")

        # Verify old password
        if not user.hashed_password or not self._security_utils.verify_password(
            old_password, user.hashed_password
        ):
            raise InvalidCredentialsError("Current password is incorrect")

        # Validate new password
        password_validation = self._password_validator.validate(new_password)
        if not password_validation["is_valid"]:
            raise ValidationError(
                f"New password validation failed: {', '.join(password_validation['errors'])}"
            )

        # Hash new password
        new_hashed_password = self._security_utils.hash_password(new_password)

        # Update user
        user.hashed_password = new_hashed_password
        self._user_manager.update_user(user)

        # Revoke all existing tokens to force re-authentication
        self._token_manager.revoke_user_tokens(user_id)

        return True

    async def change_password_async(
        self, user_id: str, old_password: str, new_password: str
    ) -> bool:
        """Change user's password (async)."""
        # Get user
        user = await self._user_manager.get_by_id_async(user_id)
        if not user:
            raise InvalidCredentialsError("User not found")

        # Verify old password
        if not user.hashed_password or not self._security_utils.verify_password(
            old_password, user.hashed_password
        ):
            raise InvalidCredentialsError("Current password is incorrect")

        # Validate new password
        password_validation = self._password_validator.validate(new_password)
        if not password_validation["is_valid"]:
            raise ValidationError(
                f"New password validation failed: {', '.join(password_validation['errors'])}"
            )

        # Hash new password
        new_hashed_password = self._security_utils.hash_password(new_password)

        # Update user
        user.hashed_password = new_hashed_password
        await self._user_manager.update_user_async(user)

        # Revoke all existing tokens to force re-authentication
        await self._token_manager.revoke_user_tokens_async(user_id)

        return True

    def reset_password(self, email: str) -> str:
        """
        Initiate password reset process.

        Args:
            email: User's email address

        Returns:
            Password reset token (in production, this would be sent via email)

        Raises:
            ValidationError: If email is invalid
        """
        # Validate email
        if not self._email_validator.validate(email):
            raise ValidationError("Invalid email format")

        try:
            # Get user by email
            user = self._user_manager.get_user_by_email(email)

            # Generate password reset token (short-lived)
            reset_token = self._token_manager.generate_token(
                user.id,
                "access",  # Use access token type but with custom claims
                {"purpose": "password_reset", "exp_minutes": 15},  # 15 minute expiry
            )

            # In production, send this token via email instead of returning it
            return reset_token.token

        except Exception:
            # Don't reveal if user exists or not for security
            # In production, always return success message
            return "password_reset_initiated"

    async def reset_password_async(self, email: str) -> str:
        """Initiate password reset process (async)."""
        # Validate email
        if not self._email_validator.validate(email):
            raise ValidationError("Invalid email format")

        try:
            # Get user by email
            user = await self._user_manager.get_user_by_email_async(email)

            # Generate password reset token (short-lived)
            reset_token = await self._token_manager.generate_token_async(
                user.id,
                "access",  # Use access token type but with custom claims
                {"purpose": "password_reset", "exp_minutes": 15},  # 15 minute expiry
            )

            # In production, send this token via email instead of returning it
            return reset_token.token

        except Exception:
            # Don't reveal if user exists or not for security
            return "password_reset_initiated"

    def confirm_password_reset(self, reset_token: str, new_password: str) -> bool:
        """
        Confirm password reset with token and new password.

        Args:
            reset_token: Password reset token
            new_password: New password

        Returns:
            True if password was reset successfully

        Raises:
            InvalidTokenError: If reset token is invalid
            ValidationError: If new password validation fails
        """
        # Validate token
        payload = self._token_manager.validate_token(reset_token)

        if payload.get("purpose") != "password_reset":
            raise InvalidCredentialsError("Invalid reset token")

        user_id = payload.get("user_id")
        if not user_id:
            raise InvalidCredentialsError("Invalid reset token")

        # Validate new password
        password_validation = self._password_validator.validate(new_password)
        if not password_validation["is_valid"]:
            raise ValidationError(
                f"Password validation failed: {', '.join(password_validation['errors'])}"
            )

        # Get user and update password
        user = self._user_manager.get_by_id(user_id)
        if not user:
            raise InvalidCredentialsError("User not found")

        # Hash new password
        new_hashed_password = self._security_utils.hash_password(new_password)
        user.hashed_password = new_hashed_password
        self._user_manager.update_user(user)

        # Revoke the reset token and all user tokens
        self._token_manager.revoke_token(reset_token)
        self._token_manager.revoke_user_tokens(user_id)

        return True

    async def confirm_password_reset_async(
        self, reset_token: str, new_password: str
    ) -> bool:
        """Confirm password reset with token and new password (async)."""
        # Validate token
        payload = await self._token_manager.validate_token_async(reset_token)

        if payload.get("purpose") != "password_reset":
            raise InvalidCredentialsError("Invalid reset token")

        user_id = payload.get("user_id")
        if not user_id:
            raise InvalidCredentialsError("Invalid reset token")

        # Validate new password
        password_validation = self._password_validator.validate(new_password)
        if not password_validation["is_valid"]:
            raise ValidationError(
                f"Password validation failed: {', '.join(password_validation['errors'])}"
            )

        # Get user and update password
        user = await self._user_manager.get_by_id_async(user_id)
        if not user:
            raise InvalidCredentialsError("User not found")

        # Hash new password
        new_hashed_password = self._security_utils.hash_password(new_password)
        user.hashed_password = new_hashed_password
        await self._user_manager.update_user_async(user)

        # Revoke the reset token and all user tokens
        await self._token_manager.revoke_token_async(reset_token)
        await self._token_manager.revoke_user_tokens_async(user_id)

        return True

    def logout(
        self, access_token: str, clear_cookies: bool = False
    ) -> Union[bool, Response]:
        """
        Logout user by revoking their access token.

        Args:
            access_token: User's access token
            clear_cookies: Whether to clear HTTP cookies

        Returns:
            True if logout was successful, or Response object if clear_cookies=True
        """
        success = self._token_manager.revoke_token(access_token)

        if clear_cookies:
            return self._create_logout_response(success)

        return success

    async def logout_async(
        self, access_token: str, clear_cookies: bool = False
    ) -> Union[bool, Response]:
        """Logout user by revoking their access token (async)."""
        success = await self._token_manager.revoke_token_async(access_token)

        if clear_cookies:
            return self._create_logout_response(success)

        return success

    def logout_all_devices(self, user_id: str) -> int:
        """
        Logout user from all devices by revoking all their tokens.

        Args:
            user_id: ID of the user

        Returns:
            Number of tokens revoked
        """
        return self._token_manager.revoke_user_tokens(user_id)

    async def logout_all_devices_async(self, user_id: str) -> int:
        """Logout user from all devices by revoking all their tokens (async)."""
        return await self._token_manager.revoke_user_tokens_async(user_id)
