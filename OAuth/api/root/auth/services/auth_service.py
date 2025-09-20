"""
Authentication service for email/password authentication.
"""

from typing import Dict, Any, Union
from auth.services.base_auth_service import BaseAuthService
from auth.models.user import User
from auth.managers.user_manager import UserManager
from auth.managers.token_manager import TokenManager
from auth.utils.security import SecurityUtils
from auth.utils.validators import EmailValidator, PasswordValidator
from auth.exceptions.auth_exceptions import (
    InvalidCredentialsError,
    InvalidTokenError,
    UserAlreadyExistsError,
    ValidationError,
)
from fastapi import Response
import logging

# Configure logging
logger = logging.getLogger(__name__)


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
        """
        self._validate_required_fields(credentials, ["email", "password"])

        email = credentials.get("email")
        password = credentials.get("password")

        if not self._email_validator.validate(email):
            raise ValidationError("Invalid email format")

        try:
            user = self._user_manager.get_user_by_email(email)
            if not user:
                raise InvalidCredentialsError("Invalid email or password")

            if not user.is_active:
                raise InvalidCredentialsError("Account is deactivated")

            if not user.hashed_password:
                raise InvalidCredentialsError(
                    "Password authentication not set up for this user"
                )

            if not self._security_utils.verify_password(password, user.hashed_password):
                raise InvalidCredentialsError("Invalid email or password")

            tokens = self._token_manager.generate_token_pair(user.id)

            return self._format_auth_response(
                user,
                tokens["access"].token,
                tokens["refresh"].token,
                set_cookies=set_cookies,
            )

        except Exception as e:
            if isinstance(e, (InvalidCredentialsError, ValidationError)):
                raise
            self._handle_auth_error(e, "email/password authentication")
            raise InvalidCredentialsError("Authentication failed") from e

    async def authenticate_async(
        self, credentials: Dict[str, Any], set_cookies: bool = False
    ) -> Union[Dict[str, Any], Response]:
        """Authenticate user with email and password (async)."""
        self._validate_required_fields(credentials, ["email", "password"])

        email = credentials.get("email")
        password = credentials.get("password")

        if not self._email_validator.validate(email):
            raise ValidationError("Invalid email format")

        try:
            user = await self._user_manager.get_user_by_email_async(email)
            if not user:
                raise InvalidCredentialsError("Invalid email or password")

            if not user.is_active:
                raise InvalidCredentialsError("Account is deactivated")

            if not user.hashed_password:
                raise InvalidCredentialsError(
                    "Password authentication not set up for this user"
                )

            if not self._security_utils.verify_password(password, user.hashed_password):
                raise InvalidCredentialsError("Invalid email or password")

            tokens = await self._token_manager.generate_token_pair_async(user.id)

            return self._format_auth_response(
                user,
                tokens["access"].token,
                tokens["refresh"].token,
                set_cookies=set_cookies,
            )

        except Exception as e:
            if isinstance(e, (InvalidCredentialsError, ValidationError)):
                raise
            self._handle_auth_error(e, "email/password authentication (async)")
            raise InvalidCredentialsError("Authentication failed") from e

    def register(self, user_data: Dict[str, Any]) -> User:
        """
        Register a new user with email and password.
        """
        self._validate_required_fields(user_data, ["email", "password"])

        email = user_data.get("email")
        password = user_data.get("password")
        first_name = user_data.get("first_name", "")
        last_name = user_data.get("last_name", "")

        if not self._email_validator.validate(email):
            raise ValidationError("Invalid email format")

        try:
            existing_user = self._user_manager.get_user_by_email(email)
            if existing_user:
                raise UserAlreadyExistsError(f"User with email {email} already exists")
        except:
            pass  # No user found, proceed with registration

        password_validation = self._password_validator.validate(password)
        if not password_validation["is_valid"]:
            raise ValidationError(
                f"Password validation failed: {', '.join(password_validation['errors'])}"
            )

        hashed_password = self._security_utils.hash_password(password)
        sanitized_data = self._sanitize_user_data(user_data)

        user = self._user_manager.create_user(
            email=email,
            hashed_password=hashed_password,
            first_name=first_name,
            last_name=last_name,
            **sanitized_data,
        )

        return user

    async def register_async(self, user_data: Dict[str, Any]) -> User:
        """Register a new user with email and password (async)."""
        self._validate_required_fields(user_data, ["email", "password"])

        email = user_data.get("email")
        password = user_data.get("password")
        first_name = user_data.get("first_name", "")
        last_name = user_data.get("last_name", "")

        if not self._email_validator.validate(email):
            raise ValidationError("Invalid email format")

        try:
            existing_user = await self._user_manager.get_user_by_email_async(email)
            if existing_user:
                raise UserAlreadyExistsError(f"User with email {email} already exists")
        except:
            pass  # No user found, proceed with registration

        password_validation = self._password_validator.validate(password)
        if not password_validation["is_valid"]:
            raise ValidationError(
                f"Password validation failed: {', '.join(password_validation['errors'])}"
            )

        hashed_password = self._security_utils.hash_password(password)
        sanitized_data = self._sanitize_user_data(user_data)

        user = await self._user_manager.create_user_async(
            email=email,
            hashed_password=hashed_password,
            first_name=first_name,
            last_name=last_name,
            **sanitized_data,
        )

        return user

    def change_password(
        self, user_id: str, old_password: str, new_password: str
    ) -> bool:
        """
        Change user's password.
        """
        try:
            user = self._user_manager.get_by_id(user_id)
            if not user:
                raise InvalidCredentialsError("User not found")

            if not user.hashed_password or not self._security_utils.verify_password(
                old_password, user.hashed_password
            ):
                raise InvalidCredentialsError("Current password is incorrect")

            password_validation = self._password_validator.validate(new_password)
            if not password_validation["is_valid"]:
                raise ValidationError(
                    f"New password validation failed: {', '.join(password_validation['errors'])}"
                )

            new_hashed_password = self._security_utils.hash_password(new_password)
            user.hashed_password = new_hashed_password
            self._user_manager.update_user(user)

            self._token_manager.revoke_user_tokens(user_id)
            return True

        except Exception as e:
            self._handle_auth_error(e, "password change")
            raise

    async def change_password_async(
        self, user_id: str, old_password: str, new_password: str
    ) -> bool:
        """Change user's password (async)."""
        try:
            user = await self._user_manager.get_by_id_async(user_id)
            if not user:
                raise InvalidCredentialsError("User not found")

            if not user.hashed_password or not self._security_utils.verify_password(
                old_password, user.hashed_password
            ):
                raise InvalidCredentialsError("Current password is incorrect")

            password_validation = self._password_validator.validate(new_password)
            if not password_validation["is_valid"]:
                raise ValidationError(
                    f"New password validation failed: {', '.join(password_validation['errors'])}"
                )

            new_hashed_password = self._security_utils.hash_password(new_password)
            user.hashed_password = new_hashed_password
            await self._user_manager.update_user_async(user)

            await self._token_manager.revoke_user_tokens_async(user_id)
            return True

        except Exception as e:
            self._handle_auth_error(e, "password change (async)")
            raise

    def reset_password(self, email: str) -> str:
        """
        Initiate password reset process.
        """
        if not self._email_validator.validate(email):
            raise ValidationError("Invalid email format")

        try:
            user = self._user_manager.get_user_by_email(email)
            if user:
                reset_token = self._token_manager.generate_token(
                    user.id,
                    "access",
                    {"purpose": "password_reset", "exp_minutes": 15},
                )
                # In production, send reset_token via email instead of returning
                logger.info(f"Password reset initiated for {email}")
                return "password_reset_initiated"
        except:
            pass  # Don't reveal if user exists

        return "password_reset_initiated"

    async def reset_password_async(self, email: str) -> str:
        """Initiate password reset process (async)."""
        if not self._email_validator.validate(email):
            raise ValidationError("Invalid email format")

        try:
            user = await self._user_manager.get_user_by_email_async(email)
            if user:
                reset_token = await self._token_manager.generate_token_async(
                    user.id,
                    "access",
                    {"purpose": "password_reset", "exp_minutes": 15},
                )
                # In production, send reset_token via email instead of returning
                logger.info(f"Password reset initiated for {email}")
                return "password_reset_initiated"
        except:
            pass  # Don't reveal if user exists

        return "password_reset_initiated"

    async def confirm_password_reset_async(
        self, reset_token: str, new_password: str
    ) -> bool:
        """Confirm password reset with token and new password (async)."""
        try:
            payload = await self._token_manager.validate_token_async(reset_token)
            if not payload.get("purpose") == "password_reset":
                raise InvalidTokenError("Invalid reset token")

            user_id = payload.get("user_id")
            if not user_id:
                raise InvalidTokenError("Invalid reset token")

            password_validation = self._password_validator.validate(new_password)
            if not password_validation["is_valid"]:
                raise ValidationError(
                    f"Password validation failed: {', '.join(password_validation['errors'])}"
                )

            user = await self._user_manager.get_by_id_async(user_id)
            if not user:
                raise InvalidCredentialsError("User not found")

            new_hashed_password = self._security_utils.hash_password(new_password)
            user.hashed_password = new_hashed_password
            await self._user_manager.update_user_async(user)

            await self._token_manager.revoke_token_async(reset_token)
            await self._token_manager.revoke_user_tokens_async(user_id)
            return True

        except Exception as e:
            self._handle_auth_error(e, "password reset confirmation (async)")
            raise

    def confirm_password_reset(self, reset_token: str, new_password: str) -> bool:
        """
        Confirm password reset with token and new password.
        """
        try:
            payload = self._token_manager.validate_token(reset_token)
            if not payload.get("purpose") == "password_reset":
                raise InvalidTokenError("Invalid reset token")

            user_id = payload.get("user_id")
            if not user_id:
                raise InvalidTokenError("Invalid reset token")

            password_validation = self._password_validator.validate(new_password)
            if not password_validation["is_valid"]:
                raise ValidationError(
                    f"Password validation failed: {', '.join(password_validation['errors'])}"
                )

            user = self._user_manager.get_by_id(user_id)
            if not user:
                raise InvalidCredentialsError("User not found")

            new_hashed_password = self._security_utils.hash_password(new_password)
            user.hashed_password = new_hashed_password
            self._user_manager.update_user(user)

            self._token_manager.revoke_token(reset_token)
            self._token_manager.revoke_user_tokens(user_id)
            return True

        except Exception as e:
            self._handle_auth_error(e, "password reset confirmation")
            raise

    def logout(
        self, access_token: str, clear_cookies: bool = False
    ) -> Union[bool, Response]:
        """
        Logout user by revoking their access token.
        """
        try:
            success = self._token_manager.revoke_token(access_token)
            if clear_cookies:
                return self._create_logout_response(success)
            return success
        except Exception as e:
            self._handle_auth_error(e, "logout")
            raise

    async def logout_async(
        self, access_token: str, clear_cookies: bool = False
    ) -> Union[bool, Response]:
        """Logout user by revoking their access token (async)."""
        try:
            success = await self._token_manager.revoke_token_async(access_token)
            if clear_cookies:
                return await self._create_logout_response(success)
            return success
        except Exception as e:
            self._handle_auth_error(e, "logout (async)")
            raise

    def logout_all_devices(self, user_id: str) -> int:
        """
        Logout user from all devices by revoking all their tokens.
        """
        try:
            return self._token_manager.revoke_user_tokens(user_id)
        except Exception as e:
            self._handle_auth_error(e, "logout all devices")
            raise

    async def logout_all_devices_async(self, user_id: str) -> int:
        """Logout user from all devices by revoking all their tokens (async)."""
        try:
            return await self._token_manager.revoke_user_tokens_async(user_id)
        except Exception as e:
            self._handle_auth_error(e, "logout all devices (async)")
            raise
