"""
Pydantic schemas for request/response validation.
Defines data models for all authentication operations.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field, field_validator
from root.authcommon.constants import (
    PASSWORD_MIN_LENGTH,
    REGEX_PASSWORD_STRENGTH,
    TOKEN_TYPE_BEARER,
    SUPPORTED_OAUTH_PROVIDERS,
    DEFAULT_ROLES,
)


class BaseAuthSchema(BaseModel):
    """Base schema with common configuration."""

    model_config = {
        "str_strip_whitespace": True,
        "validate_assignment": True,
        "use_enum_values": True,
    }


class UserIn(BaseAuthSchema):
    """Schema for user input during registration/login."""

    email: EmailStr = Field(..., description="User email address")
    password: str = Field(
        ...,
        min_length=PASSWORD_MIN_LENGTH,
        description=f"Password (minimum {PASSWORD_MIN_LENGTH} characters)",
    )

    @field_validator("password")
    def validate_password_strength(cls, v):
        import re

        if not re.match(REGEX_PASSWORD_STRENGTH, v):
            raise ValueError(
                "Password must contain at least one uppercase letter, "
                "one lowercase letter, one digit, and one special character"
            )
        return v


class UserRegistration(UserIn):
    """Schema for user registration."""

    first_name: Optional[str] = Field(None, max_length=50, description="First name")
    last_name: Optional[str] = Field(None, max_length=50, description="Last name")
    roles: List[str] = Field(default=DEFAULT_ROLES, description="User roles")

    @field_validator("roles")
    def validate_roles(cls, v):
        if not v:
            return DEFAULT_ROLES
        return v


class UserLogin(BaseAuthSchema):
    """Schema for user login."""

    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., description="User password")
    otp_code: Optional[str] = Field(
        None, min_length=6, max_length=6, description="OTP code"
    )
    remember_me: bool = Field(default=False, description="Remember login session")


class TokenResponse(BaseAuthSchema):
    """Schema for token response."""

    access_token: str = Field(..., description="JWT access token")
    refresh_token: Optional[str] = Field(None, description="JWT refresh token")
    token_type: str = Field(default=TOKEN_TYPE_BEARER, description="Token type")
    expires_in: int = Field(..., description="Token expiry time in seconds")
    user_info: Optional[Dict[str, Any]] = Field(None, description="User information")


class TokenRefresh(BaseAuthSchema):
    """Schema for token refresh request."""

    refresh_token: str = Field(..., description="Refresh token")


class OTPRequest(BaseAuthSchema):
    """Schema for OTP request."""

    email: EmailStr = Field(..., description="User email address")
    action: str = Field(default="login", description="Action requiring OTP")


class OTPVerification(BaseAuthSchema):
    """Schema for OTP verification."""

    email: EmailStr = Field(..., description="User email address")
    otp_code: str = Field(..., min_length=6, max_length=6, description="OTP code")
    action: str = Field(default="login", description="Action being verified")


class PasswordResetRequest(BaseAuthSchema):
    """Schema for password reset request."""

    email: EmailStr = Field(..., description="User email address")


class PasswordReset(BaseAuthSchema):
    """Schema for password reset."""

    token: str = Field(..., description="Password reset token")
    new_password: str = Field(
        ...,
        min_length=PASSWORD_MIN_LENGTH,
        description=f"New password (minimum {PASSWORD_MIN_LENGTH} characters)",
    )

    @field_validator("new_password")
    def validate_password_strength(cls, v):
        import re

        if not re.match(REGEX_PASSWORD_STRENGTH, v):
            raise ValueError(
                "Password must contain at least one uppercase letter, "
                "one lowercase letter, one digit, and one special character"
            )
        return v


class PasswordChange(BaseAuthSchema):
    """Schema for password change (authenticated user)."""

    current_password: str = Field(..., description="Current password")
    new_password: str = Field(
        ...,
        min_length=PASSWORD_MIN_LENGTH,
        description=f"New password (minimum {PASSWORD_MIN_LENGTH} characters)",
    )

    @field_validator("new_password")
    def validate_password_strength(cls, v):
        import re

        if not re.match(REGEX_PASSWORD_STRENGTH, v):
            raise ValueError(
                "Password must contain at least one uppercase letter, "
                "one lowercase letter, one digit, and one special character"
            )
        return v


class SocialLoginRequest(BaseAuthSchema):
    """Schema for social login request."""

    provider: str = Field(..., description="OAuth provider")
    redirect_uri: Optional[str] = Field(
        None, description="Redirect URI after authentication"
    )

    @field_validator("provider")
    def validate_provider(cls, v):
        if v not in SUPPORTED_OAUTH_PROVIDERS:
            raise ValueError(f"Provider must be one of {SUPPORTED_OAUTH_PROVIDERS}")
        return v


class SocialLoginCallback(BaseAuthSchema):
    """Schema for social login callback."""

    provider: str = Field(..., description="OAuth provider")
    code: str = Field(..., description="Authorization code")
    state: Optional[str] = Field(None, description="CSRF state parameter")

    @field_validator("provider")
    def validate_provider(cls, v):
        if v not in SUPPORTED_OAUTH_PROVIDERS:
            raise ValueError(f"Provider must be one of {SUPPORTED_OAUTH_PROVIDERS}")
        return v


class UserProfile(BaseAuthSchema):
    """Schema for user profile information."""

    id: str = Field(..., description="User ID")
    email: EmailStr = Field(..., description="User email")
    first_name: Optional[str] = Field(None, description="First name")
    last_name: Optional[str] = Field(None, description="Last name")
    roles: List[str] = Field(default=DEFAULT_ROLES, description="User roles")
    is_active: bool = Field(default=True, description="User active status")
    is_verified: bool = Field(default=False, description="Email verification status")
    created_at: Optional[datetime] = Field(None, description="Account creation date")
    last_login: Optional[datetime] = Field(None, description="Last login date")
    oauth_providers: List[str] = Field(
        default=[], description="Connected OAuth providers"
    )


class UserUpdate(BaseAuthSchema):
    """Schema for user profile updates."""

    first_name: Optional[str] = Field(None, max_length=50, description="First name")
    last_name: Optional[str] = Field(None, max_length=50, description="Last name")


class RoleAssignment(BaseAuthSchema):
    """Schema for role assignment."""

    user_id: str = Field(..., description="User ID")
    roles: List[str] = Field(..., description="Roles to assign")

    @field_validator("roles")
    def validate_roles_not_empty(cls, v):
        if not v:
            raise ValueError("At least one role must be provided")
        return v


class PermissionCheck(BaseAuthSchema):
    """Schema for permission checking."""

    user_id: str = Field(..., description="User ID")
    permission: str = Field(..., description="Permission to check")
    resource: Optional[str] = Field(None, description="Resource identifier")


class AuthStatus(BaseAuthSchema):
    """Schema for authentication status."""

    is_authenticated: bool = Field(..., description="Authentication status")
    user: Optional[UserProfile] = Field(
        None, description="User profile if authenticated"
    )
    permissions: List[str] = Field(default=[], description="User permissions")
    expires_at: Optional[datetime] = Field(None, description="Token expiry time")


class APIResponse(BaseAuthSchema):
    """Generic API response schema."""

    success: bool = Field(..., description="Operation success status")
    message: str = Field(..., description="Response message")
    data: Optional[Dict[str, Any]] = Field(None, description="Response data")
    error_code: Optional[str] = Field(None, description="Error code if applicable")


class HealthCheck(BaseAuthSchema):
    """Schema for health check response."""

    status: str = Field(..., description="Service status")
    version: str = Field(..., description="Service version")
    timestamp: datetime = Field(..., description="Check timestamp")
    dependencies: Dict[str, str] = Field(default={}, description="Dependency status")
