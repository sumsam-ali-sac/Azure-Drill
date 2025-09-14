"""
Main AuthManager class that orchestrates all authentication flows.
This is the primary interface for authentication operations.
"""

import asyncio
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import logging

from auth.common.config import config
from auth.common.exceptions import (
    InvalidCredentialsError,
    OTPInvalidError,
    TokenExpiredError,
    RateLimitExceededError,
    InsufficientPermissionsError,
    UserNotFoundError,
    AccountLockedError,
)
from root.ai_query_engine.core.auth.common.schemas import (
    UserIn,
    TokenResponse,
    ResetRequest,
    OTPRequest,
    SocialLoginRequest,
    UserProfile,
)
from auth.security.password_utils import PasswordManager
from auth.security.otp_utils import OTPManager
from auth.security.token_utils import TokenManager
from auth.oauth.oauth_manager import OAuthManager
from auth.rate_limiting import RateLimiter
from auth.email import EmailManager
from auth.rbac.rbac_manager import RBACManager
from auth.validation import InputValidator

logger = logging.getLogger(__name__)


class AuthManager:
    """
    Central authentication manager that coordinates all auth operations.

    This class provides a high-level interface for:
    - User registration and login
    - Password management and reset
    - OTP/2FA operations
    - Social authentication
    - Token management
    - Role-based access control
    """

    def __init__(self):
        self.password_manager = PasswordManager()
        self.otp_manager = OTPManager()
        self.token_manager = TokenManager()
        self.oauth_manager = OAuthManager()
        self.rate_limiter = RateLimiter()
        self.email_manager = EmailManager()
        self.rbac_manager = RBACManager()
        self.validator = InputValidator()

        logger.info("AuthManager initialized with all components")

    async def register_user(
        self, user_data: UserIn, request_ip: str = None
    ) -> TokenResponse:
        """
        Register a new user with email verification and optional OTP.

        Args:
            user_data: User registration data
            request_ip: Client IP for rate limiting

        Returns:
            TokenResponse with access and refresh tokens

        Raises:
            RateLimitExceededError: Too many registration attempts
            InvalidCredentialsError: Invalid input data
        """
        # Rate limiting
        await self.rate_limiter.check_limit(
            f"register:{request_ip or 'unknown'}", config.RATE_LIMIT_LOGIN_PER_MIN, 60
        )

        # Validate input
        self.validator.validate_email(user_data.email)
        self.validator.validate_password_strength(user_data.password)

        # Hash password
        hashed_password = self.password_manager.hash_password(user_data.password)

        # Generate user profile
        user_profile = UserProfile(
            email=user_data.email,
            hashed_password=hashed_password,
            roles=["user"],  # Default role
            is_verified=False,
            created_at=datetime.utcnow(),
            last_login=None,
        )

        # Send verification email if OTP is required
        if config.REQUIRE_OTP:
            otp_secret = self.otp_manager.generate_secret()
            otp_code = self.otp_manager.generate_code(otp_secret)

            await self.email_manager.send_verification_email(
                user_data.email, otp_code, user_data.first_name or "User"
            )

            # Store OTP secret temporarily (in production, use Redis/cache)
            # For now, we'll include it in the token payload for stateless operation
            temp_token = self.token_manager.create_token(
                {
                    "sub": user_data.email,
                    "type": "verification",
                    "otp_secret": otp_secret,
                    "user_data": user_profile.dict(),
                },
                expires_minutes=10,
            )

            return TokenResponse(
                access_token=temp_token,
                refresh_token="",
                token_type="verification",
                requires_verification=True,
            )

        # Create tokens for immediate login
        access_token = self.token_manager.create_token(
            {
                "sub": user_data.email,
                "roles": user_profile.roles,
                "user_id": user_profile.user_id,
                "is_verified": user_profile.is_verified,
            },
            expires_minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES,
        )

        refresh_token = self.token_manager.create_token(
            {
                "sub": user_data.email,
                "type": "refresh",
                "user_id": user_profile.user_id,
            },
            expires_minutes=config.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60,
        )

        logger.info(f"User registered successfully: {user_data.email}")

        return TokenResponse(
            access_token=access_token, refresh_token=refresh_token, token_type="bearer"
        )

    async def verify_registration(
        self, verification_token: str, otp_code: str
    ) -> TokenResponse:
        """
        Verify user registration with OTP code.

        Args:
            verification_token: Temporary verification token
            otp_code: OTP code from email

        Returns:
            TokenResponse with access and refresh tokens
        """
        # Verify the temporary token
        payload = self.token_manager.verify_token(verification_token)

        if payload.get("type") != "verification":
            raise InvalidCredentialsError("Invalid verification token")

        # Verify OTP
        otp_secret = payload.get("otp_secret")
        if not self.otp_manager.verify_code(otp_code, otp_secret):
            raise OTPInvalidError("Invalid or expired OTP code")

        # Extract user data and create verified profile
        user_data = payload.get("user_data", {})
        user_profile = UserProfile(**user_data)
        user_profile.is_verified = True
        user_profile.verified_at = datetime.utcnow()

        # Create final tokens
        access_token = self.token_manager.create_token(
            {
                "sub": user_profile.email,
                "roles": user_profile.roles,
                "user_id": user_profile.user_id,
                "is_verified": True,
            },
            expires_minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES,
        )

        refresh_token = self.token_manager.create_token(
            {
                "sub": user_profile.email,
                "type": "refresh",
                "user_id": user_profile.user_id,
            },
            expires_minutes=config.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60,
        )

        logger.info(f"User verification completed: {user_profile.email}")

        return TokenResponse(
            access_token=access_token, refresh_token=refresh_token, token_type="bearer"
        )

    async def login_email_password(
        self,
        email: str,
        password: str,
        otp_code: Optional[str] = None,
        request_ip: str = None,
    ) -> TokenResponse:
        """
        Authenticate user with email and password, with optional OTP.

        Args:
            email: User email
            password: User password
            otp_code: Optional OTP code for 2FA
            request_ip: Client IP for rate limiting

        Returns:
            TokenResponse with tokens or OTP requirement
        """
        # Rate limiting
        await self.rate_limiter.check_limit(
            f"login:{request_ip or 'unknown'}", config.RATE_LIMIT_LOGIN_PER_MIN, 60
        )

        # Validate input
        self.validator.validate_email(email)

        # In a real implementation, you would fetch user from database
        # For this stateless example, we'll simulate user lookup
        # This would typically be: user = await self.user_repository.get_by_email(email)

        # Simulate user data (in production, fetch from database)
        simulated_user = self._simulate_user_lookup(email)
        if not simulated_user:
            raise UserNotFoundError("User not found")

        # Check if account is locked
        if simulated_user.get("is_locked", False):
            raise AccountLockedError(
                "Account is locked due to too many failed attempts"
            )

        # Verify password
        if not self.password_manager.verify_password(
            password, simulated_user["hashed_password"]
        ):
            # Increment failed attempts (in production, update database)
            await self._handle_failed_login(email, request_ip)
            raise InvalidCredentialsError("Invalid email or password")

        # Handle OTP if required
        if config.REQUIRE_OTP and not otp_code:
            # Generate and send OTP
            otp_secret = self.otp_manager.generate_secret()
            otp_code_generated = self.otp_manager.generate_code(otp_secret)

            await self.email_manager.send_otp_email(
                email, otp_code_generated, simulated_user.get("first_name", "User")
            )

            # Return temporary token requiring OTP
            temp_token = self.token_manager.create_token(
                {
                    "sub": email,
                    "type": "otp_required",
                    "otp_secret": otp_secret,
                    "user_data": simulated_user,
                },
                expires_minutes=5,
            )

            return TokenResponse(
                access_token=temp_token,
                refresh_token="",
                token_type="otp_required",
                requires_otp=True,
            )

        elif config.REQUIRE_OTP and otp_code:
            # This would be a second call with OTP - verify the temp token first
            # In practice, you'd pass the temp token as well
            pass

        # Create final tokens
        access_token = self.token_manager.create_token(
            {
                "sub": email,
                "roles": simulated_user.get("roles", ["user"]),
                "user_id": simulated_user.get("user_id"),
                "is_verified": simulated_user.get("is_verified", True),
            },
            expires_minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES,
        )

        refresh_token = self.token_manager.create_token(
            {"sub": email, "type": "refresh", "user_id": simulated_user.get("user_id")},
            expires_minutes=config.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60,
        )

        # Reset failed attempts on successful login
        await self._reset_failed_attempts(email)

        logger.info(f"User logged in successfully: {email}")

        return TokenResponse(
            access_token=access_token, refresh_token=refresh_token, token_type="bearer"
        )

    async def verify_otp_login(self, temp_token: str, otp_code: str) -> TokenResponse:
        """
        Complete login process by verifying OTP code.

        Args:
            temp_token: Temporary token from initial login
            otp_code: OTP code from email/app

        Returns:
            TokenResponse with final access and refresh tokens
        """
        # Verify temporary token
        payload = self.token_manager.verify_token(temp_token)

        if payload.get("type") != "otp_required":
            raise InvalidCredentialsError("Invalid temporary token")

        # Verify OTP
        otp_secret = payload.get("otp_secret")
        if not self.otp_manager.verify_code(otp_code, otp_secret):
            raise OTPInvalidError("Invalid or expired OTP code")

        # Extract user data
        user_data = payload.get("user_data", {})
        email = payload.get("sub")

        # Create final tokens
        access_token = self.token_manager.create_token(
            {
                "sub": email,
                "roles": user_data.get("roles", ["user"]),
                "user_id": user_data.get("user_id"),
                "is_verified": user_data.get("is_verified", True),
            },
            expires_minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES,
        )

        refresh_token = self.token_manager.create_token(
            {"sub": email, "type": "refresh", "user_id": user_data.get("user_id")},
            expires_minutes=config.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60,
        )

        logger.info(f"OTP verification completed for: {email}")

        return TokenResponse(
            access_token=access_token, refresh_token=refresh_token, token_type="bearer"
        )

    async def refresh_token(self, refresh_token: str) -> TokenResponse:
        """
        Refresh access token using refresh token.

        Args:
            refresh_token: Valid refresh token

        Returns:
            TokenResponse with new access token
        """
        try:
            payload = self.token_manager.verify_token(refresh_token)

            if payload.get("type") != "refresh":
                raise InvalidCredentialsError("Invalid refresh token")

            # Create new access token
            new_access_token = self.token_manager.create_token(
                {
                    "sub": payload["sub"],
                    "user_id": payload.get("user_id"),
                    # Note: roles would be fetched from database in production
                    "roles": ["user"],  # Simplified for stateless example
                },
                expires_minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES,
            )

            return TokenResponse(
                access_token=new_access_token,
                refresh_token=refresh_token,  # Keep same refresh token
                token_type="bearer",
            )

        except Exception as e:
            logger.error(f"Token refresh failed: {str(e)}")
            raise TokenExpiredError("Refresh token is invalid or expired")

    async def initiate_password_reset(
        self, email: str, request_ip: str = None
    ) -> Dict[str, str]:
        """
        Initiate password reset process.

        Args:
            email: User email
            request_ip: Client IP for rate limiting

        Returns:
            Success message
        """
        # Rate limiting
        await self.rate_limiter.check_limit(
            f"reset:{request_ip or 'unknown'}", config.RATE_LIMIT_RESET_PER_HOUR, 3600
        )

        self.validator.validate_email(email)

        # Generate reset token
        reset_token = self.token_manager.create_token(
            {"sub": email, "type": "password_reset"},
            expires_minutes=15,  # Short expiry for security
        )

        # Send reset email
        await self.email_manager.send_password_reset_email(email, reset_token)

        logger.info(f"Password reset initiated for: {email}")

        return {"message": "Password reset email sent"}

    async def complete_password_reset(
        self, reset_token: str, new_password: str
    ) -> Dict[str, str]:
        """
        Complete password reset with new password.

        Args:
            reset_token: Password reset token from email
            new_password: New password

        Returns:
            Success message
        """
        # Verify reset token
        payload = self.token_manager.verify_token(reset_token)

        if payload.get("type") != "password_reset":
            raise InvalidCredentialsError("Invalid reset token")

        # Validate new password
        self.validator.validate_password_strength(new_password)

        # Hash new password
        hashed_password = self.password_manager.hash_password(new_password)

        # In production, update password in database
        # await self.user_repository.update_password(payload["sub"], hashed_password)

        logger.info(f"Password reset completed for: {payload['sub']}")

        return {"message": "Password reset successfully"}

    def _simulate_user_lookup(self, email: str) -> Optional[Dict[str, Any]]:
        """
        Simulate user lookup from database.
        In production, this would be a database query.
        """
        # This is just for demonstration - replace with actual database lookup
        if email == "test@example.com":
            return {
                "user_id": "user_123",
                "email": email,
                "hashed_password": self.password_manager.hash_password(
                    "TestPassword123!"
                ),
                "roles": ["user"],
                "is_verified": True,
                "is_locked": False,
                "failed_attempts": 0,
                "first_name": "Test",
            }
        return None

    async def _handle_failed_login(self, email: str, request_ip: str = None):
        """Handle failed login attempt - increment counter and potentially lock account."""
        # In production, update database with failed attempt count
        # If failed_attempts >= threshold, lock account
        pass

    async def _reset_failed_attempts(self, email: str):
        """Reset failed login attempts counter."""
        # In production, reset failed_attempts in database
        pass
