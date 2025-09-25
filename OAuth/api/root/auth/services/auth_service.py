"""
Authentication service for email/password authentication.
"""

from typing import Dict, Any, Optional, Union
from root.auth.services.base_auth_service import BaseAuthService
from root.auth.models.user import User
from root.auth.managers.user_manager import UserManager
from root.auth.managers.token_manager import TokenManager
from root.auth.utils.security import SecurityUtils
from root.auth.utils.validators import EmailValidator, PasswordValidator
from root.auth.exceptions.auth_exceptions import (
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
        self._security_utils = (
            security_utils  # Kept for compatibility, but prefer _get_security_utils()
        )
        self._email_validator = EmailValidator()
        self._password_validator = PasswordValidator()

    def authenticate(
        self, credentials: Dict[str, Any], set_cookies: bool = False
    ) -> Union[Dict[str, Any], Response]:
        """
        Authenticate user with email and password.
        """
        if not isinstance(credentials, dict):
            raise ValidationError("Credentials must be a dictionary")
        self._validate_required_fields(credentials, ["email", "password"])

        email = credentials.get("email")
        password = credentials.get("password")

        if not isinstance(email, str) or not isinstance(password, str):
            raise ValidationError("Email and password must be strings")
        if not self._email_validator.validate(email):
            raise ValidationError("Invalid email format")

        try:
            user = self._user_manager.get_user_by_email(email)
            if not user:
                logger.warning(
                    f"Authentication failed: No user found for email {email}"
                )
                raise InvalidCredentialsError("Invalid email or password")

            if not user.is_active:
                logger.warning(
                    f"Authentication failed: Account deactivated for {email}"
                )
                raise InvalidCredentialsError("Account is deactivated")

            if not user.hashed_password:
                logger.error(f"Authentication failed: No password set for {email}")
                raise InvalidCredentialsError(
                    "Password authentication not set up for this user"
                )

            if not self._get_security_utils().verify_password(
                password, user.hashed_password
            ):
                logger.warning(f"Authentication failed: Invalid password for {email}")
                raise InvalidCredentialsError("Invalid email or password")

            tokens = self._token_manager.generate_token_pair(user.id)
            logger.info(f"User authenticated successfully: {email}")

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
        if not isinstance(credentials, dict):
            raise ValidationError("Credentials must be a dictionary")
        self._validate_required_fields(credentials, ["email", "password"])

        email = credentials.get("email")
        password = credentials.get("password")

        if not isinstance(email, str) or not isinstance(password, str):
            raise ValidationError("Email and password must be strings")
        if not self._email_validator.validate(email):
            raise ValidationError("Invalid email format")

        try:
            user = await self._user_manager.get_user_by_email_async(email)
            if not user:
                logger.warning(
                    f"Async authentication failed: No user found for email {email}"
                )
                raise InvalidCredentialsError("Invalid email or password")

            if not user.is_active:
                logger.warning(
                    f"Async authentication failed: Account deactivated for {email}"
                )
                raise InvalidCredentialsError("Account is deactivated")

            if not user.hashed_password:
                logger.error(
                    f"Async authentication failed: No password set for {email}"
                )
                raise InvalidCredentialsError(
                    "Password authentication not set up for this user"
                )

            if not self._get_security_utils().verify_password(
                password, user.hashed_password
            ):
                logger.warning(
                    f"Async authentication failed: Invalid password for {email}"
                )
                raise InvalidCredentialsError("Invalid email or password")

            tokens = await self._token_manager.generate_token_pair_async(user.id)
            logger.info(f"User authenticated successfully (async): {email}")

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
        if not isinstance(user_data, dict):
            raise ValidationError("User data must be a dictionary")
        self._validate_required_fields(user_data, ["email", "password"])

        email = user_data.get("email")
        password = user_data.get("password")
        first_name = user_data.get("first_name", "")
        last_name = user_data.get("last_name", "")

        if not isinstance(email, str) or not isinstance(password, str):
            raise ValidationError("Email and password must be strings")
        if not self._email_validator.validate(email):
            raise ValidationError("Invalid email format")

        try:
            existing_user = self._user_manager.get_user_by_email(email)
            if existing_user:
                logger.warning(
                    f"Registration failed: User with email {email} already exists"
                )
                raise UserAlreadyExistsError(f"User with email {email} already exists")
        except Exception as e:
            logger.debug(f"No existing user found for email {email}: {str(e)}")
            pass  # No user found, proceed with registration

        password_validation = self._password_validator.validate(password)
        if not password_validation["is_valid"]:
            raise ValidationError(
                f"Password validation failed: {', '.join(password_validation['errors'])}"
            )

        hashed_password = self._get_security_utils().hash_password(password)
        sanitized_data = self._sanitize_user_data(user_data)

        try:
            user = self._user_manager.create_user(
                email=email,
                hashed_password=hashed_password,
                first_name=first_name,
                last_name=last_name,
                **sanitized_data,
            )
            logger.info(f"User registered successfully: {email}")
            return user
        except Exception as e:
            self._handle_auth_error(e, "user registration")
            raise

    async def register_async(self, user_data: Dict[str, Any]) -> User:
        """Register a new user with email and password (async)."""
        if not isinstance(user_data, dict):
            raise ValidationError("User data must be a dictionary")
        self._validate_required_fields(user_data, ["email", "password"])

        email = user_data.get("email")
        password = user_data.get("password")
        first_name = user_data.get("first_name", "")
        last_name = user_data.get("last_name", "")

        if not isinstance(email, str) or not isinstance(password, str):
            raise ValidationError("Email and password must be strings")
        if not self._email_validator.validate(email):
            raise ValidationError("Invalid email format")

        try:
            existing_user = await self._user_manager.get_user_by_email_async(email)
            if existing_user:
                logger.warning(
                    f"Async registration failed: User with email {email} already exists"
                )
                raise UserAlreadyExistsError(f"User with email {email} already exists")
        except Exception as e:
            logger.debug(f"No existing user found for email {email}: {str(e)}")
            pass  # No user found, proceed with registration

        password_validation = self._password_validator.validate(password)
        if not password_validation["is_valid"]:
            raise ValidationError(
                f"Password validation failed: {', '.join(password_validation['errors'])}"
            )

        hashed_password = self._get_security_utils().hash_password(password)
        sanitized_data = self._sanitize_user_data(user_data)

        try:
            user = await self._user_manager.create_user_async(
                email=email,
                hashed_password=hashed_password,
                first_name=first_name,
                last_name=last_name,
                **sanitized_data,
            )
            logger.info(f"User registered successfully (async): {email}")
            return user
        except Exception as e:
            self._handle_auth_error(e, "user registration (async)")
            raise

    def change_password(
        self, user_id: str, old_password: str, new_password: str
    ) -> bool:
        """
        Change user's password.
        """
        if (
            not isinstance(user_id, str)
            or not isinstance(old_password, str)
            or not isinstance(new_password, str)
        ):
            raise ValidationError(
                "User ID, old password, and new password must be strings"
            )

        try:
            user = self._user_manager.get_by_id(user_id)
            if not user:
                logger.warning(
                    f"Password change failed: User not found for ID {user_id}"
                )
                raise InvalidCredentialsError("User not found")

            if (
                not user.hashed_password
                or not self._get_security_utils().verify_password(
                    old_password, user.hashed_password
                )
            ):
                logger.warning(
                    f"Password change failed: Invalid current password for user {user_id}"
                )
                raise InvalidCredentialsError("Current password is incorrect")

            password_validation = self._password_validator.validate(new_password)
            if not password_validation["is_valid"]:
                raise ValidationError(
                    f"New password validation failed: {', '.join(password_validation['errors'])}"
                )

            new_hashed_password = self._get_security_utils().hash_password(new_password)
            user.hashed_password = new_hashed_password
            self._user_manager.update_user(user)

            self._token_manager.revoke_user_tokens(user_id)
            logger.info(f"Password changed successfully for user {user_id}")
            return True

        except Exception as e:
            if isinstance(e, (InvalidCredentialsError, ValidationError)):
                raise
            self._handle_auth_error(e, "password change")
            raise

    async def change_password_async(
        self, user_id: str, old_password: str, new_password: str
    ) -> bool:
        """Change user's password (async)."""
        if (
            not isinstance(user_id, str)
            or not isinstance(old_password, str)
            or not isinstance(new_password, str)
        ):
            raise ValidationError(
                "User ID, old password, and new password must be strings"
            )

        try:
            user = await self._user_manager.get_by_id_async(user_id)
            if not user:
                logger.warning(
                    f"Async password change failed: User not found for ID {user_id}"
                )
                raise InvalidCredentialsError("User not found")

            if (
                not user.hashed_password
                or not self._get_security_utils().verify_password(
                    old_password, user.hashed_password
                )
            ):
                logger.warning(
                    f"Async password change failed: Invalid current password for user {user_id}"
                )
                raise InvalidCredentialsError("Current password is incorrect")

            password_validation = self._password_validator.validate(new_password)
            if not password_validation["is_valid"]:
                raise ValidationError(
                    f"New password validation failed: {', '.join(password_validation['errors'])}"
                )

            new_hashed_password = self._get_security_utils().hash_password(new_password)
            user.hashed_password = new_hashed_password
            await self._user_manager.update_user_async(user)

            await self._token_manager.revoke_user_tokens_async(user_id)
            logger.info(f"Password changed successfully (async) for user {user_id}")
            return True

        except Exception as e:
            if isinstance(e, (InvalidCredentialsError, ValidationError)):
                raise
            self._handle_auth_error(e, "password change (async)")
            raise

    def reset_password(self, email: str) -> str:
        """
        Initiate password reset process.
        """
        if not isinstance(email, str):
            raise ValidationError("Email must be a string")
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
        except Exception as e:
            logger.debug(f"No user found or error during reset for {email}: {str(e)}")
            pass  # Don't reveal if user exists

        return "password_reset_initiated"

    async def reset_password_async(self, email: str) -> str:
        """Initiate password reset process (async)."""
        if not isinstance(email, str):
            raise ValidationError("Email must be a string")
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
                logger.info(f"Password reset initiated (async) for {email}")
                return "password_reset_initiated"
        except Exception as e:
            logger.debug(
                f"No user found or error during async reset for {email}: {str(e)}"
            )
            pass  # Don't reveal if user exists

        return "password_reset_initiated"

    def confirm_password_reset(self, reset_token: str, new_password: str) -> bool:
        """
        Confirm password reset with token and new password.
        """
        if not isinstance(reset_token, str) or not isinstance(new_password, str):
            raise ValidationError("Reset token and new password must be strings")

        try:
            payload = self._token_manager.validate_token(reset_token)
            if not self._get_security_utils().constant_time_compare(
                payload.get("purpose", ""), "password_reset"
            ):
                logger.warning("Password reset failed: Invalid reset token purpose")
                raise InvalidTokenError("Invalid reset token")

            user_id = payload.get("user_id")
            if not user_id:
                logger.warning(
                    "Password reset failed: Invalid reset token (no user_id)"
                )
                raise InvalidTokenError("Invalid reset token")

            password_validation = self._password_validator.validate(new_password)
            if not password_validation["is_valid"]:
                raise ValidationError(
                    f"Password validation failed: {', '.join(password_validation['errors'])}"
                )

            user = self._user_manager.get_by_id(user_id)
            if not user:
                logger.warning(
                    f"Password reset failed: User not found for ID {user_id}"
                )
                raise InvalidCredentialsError("User not found")

            new_hashed_password = self._get_security_utils().hash_password(new_password)
            user.hashed_password = new_hashed_password
            self._user_manager.update_user(user)

            self._token_manager.revoke_token(reset_token)
            self._token_manager.revoke_user_tokens(user_id)
            logger.info(f"Password reset confirmed for user {user_id}")
            return True

        except Exception as e:
            if isinstance(
                e, (InvalidCredentialsError, InvalidTokenError, ValidationError)
            ):
                raise
            self._handle_auth_error(e, "password reset confirmation")
            raise

    async def confirm_password_reset_async(
        self, reset_token: str, new_password: str
    ) -> bool:
        """Confirm password reset with token and new password (async)."""
        if not isinstance(reset_token, str) or not isinstance(new_password, str):
            raise ValidationError("Reset token and new password must be strings")

        try:
            payload = await self._token_manager.validate_token_async(reset_token)
            if not self._get_security_utils().constant_time_compare(
                payload.get("purpose", ""), "password_reset"
            ):
                logger.warning(
                    "Async password reset failed: Invalid reset token purpose"
                )
                raise InvalidTokenError("Invalid reset token")

            user_id = payload.get("user_id")
            if not user_id:
                logger.warning(
                    "Async password reset failed: Invalid reset token (no user_id)"
                )
                raise InvalidTokenError("Invalid reset token")

            password_validation = self._password_validator.validate(new_password)
            if not password_validation["is_valid"]:
                raise ValidationError(
                    f"Password validation failed: {', '.join(password_validation['errors'])}"
                )

            user = await self._user_manager.get_by_id_async(user_id)
            if not user:
                logger.warning(
                    f"Async password reset failed: User not found for ID {user_id}"
                )
                raise InvalidCredentialsError("User not found")

            new_hashed_password = self._get_security_utils().hash_password(new_password)
            user.hashed_password = new_hashed_password
            await self._user_manager.update_user_async(user)

            await self._token_manager.revoke_token_async(reset_token)
            await self._token_manager.revoke_user_tokens_async(user_id)
            logger.info(f"Password reset confirmed (async) for user {user_id}")
            return True

        except Exception as e:
            if isinstance(
                e, (InvalidCredentialsError, InvalidTokenError, ValidationError)
            ):
                raise
            self._handle_auth_error(e, "password reset confirmation (async)")
            raise

    def logout(
        self, access_token: str, clear_cookies: bool = False
    ) -> Union[bool, Response]:
        """
        Logout user by revoking their access token.
        """
        if not isinstance(access_token, str):
            raise ValidationError("Access token must be a string")

        try:
            success = self._token_manager.revoke_token(access_token)
            logger.info(f"User logged out: {success}")
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
        if not isinstance(access_token, str):
            raise ValidationError("Access token must be a string")

        try:
            success = await self._token_manager.revoke_token_async(access_token)
            logger.info(f"User logged out (async): {success}")
            if clear_cookies:
                return self._create_logout_response(success)
            return success
        except Exception as e:
            self._handle_auth_error(e, "logout (async)")
            raise

    def logout_all_devices(self, user_id: str) -> int:
        """
        Logout user from all devices by revoking all their tokens.
        """
        if not isinstance(user_id, str):
            raise ValidationError("User ID must be a string")

        try:
            count = self._token_manager.revoke_user_tokens(user_id)
            logger.info(f"Logged out user {user_id} from {count} devices")
            return count
        except Exception as e:
            self._handle_auth_error(e, "logout all devices")
            raise

    async def logout_all_devices_async(self, user_id: str) -> int:
        """Logout user from all devices by revoking all their tokens (async)."""
        if not isinstance(user_id, str):
            raise ValidationError("User ID must be a string")

        try:
            count = await self._token_manager.revoke_user_tokens_async(user_id)
            logger.info(f"Logged out user {user_id} from {count} devices (async)")
            return count
        except Exception as e:
            self._handle_auth_error(e, "logout all devices (async)")
            raise
