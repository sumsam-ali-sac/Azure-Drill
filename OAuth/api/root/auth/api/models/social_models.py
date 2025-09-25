"""
Social authentication API request and response models.
"""

from pydantic import BaseModel, Field
from typing import Optional


class SocialAuthRequest(BaseModel):
    """Request model for social authentication."""

    provider: str = Field(..., description="OAuth provider name (google, azure)")
    auth_code: str = Field(..., description="Authorization code from provider")
    state: Optional[str] = Field(
        None, description="State parameter for CSRF protection"
    )
    set_cookies: bool = Field(
        default=False, description="Whether to set authentication cookies"
    )


class SocialAuthResponse(BaseModel):
    """Response model for social authentication."""

    user: dict = Field(..., description="User information")
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(..., description="Token type (bearer)")
    is_new_user: bool = Field(
        ..., description="Whether this is a newly registered user"
    )


# Request/Response models
class AuthUrlRequest(BaseModel):
    """Request model for getting OAuth authorization URL."""

    provider: str = Field(..., description="OAuth provider name (google, azure)")
    state: Optional[str] = Field(
        None, description="Optional state parameter for CSRF protection"
    )


class AuthUrlResponse(BaseModel):
    """Response model for OAuth authorization URL."""

    auth_url: str = Field(..., description="OAuth authorization URL")
    provider: str = Field(..., description="OAuth provider name")


class LinkProviderRequest(BaseModel):
    """Request model for linking social provider."""

    provider: str = Field(..., description="OAuth provider name (google, azure)")
    code: str = Field(..., description="Authorization code from OAuth provider")
    state: Optional[str] = Field(
        None, description="State parameter for CSRF protection"
    )


class UnlinkProviderRequest(BaseModel):
    """Request model for unlinking social provider."""

    provider: str = Field(..., description="OAuth provider name to unlink")


class AuthResponse(BaseModel):
    """Response model for social authentication."""

    user: dict = Field(..., description="User information")
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(..., description="Token type (bearer)")
    provider: str = Field(..., description="OAuth provider used")


class UserResponse(BaseModel):
    """Response model for user information."""

    user: dict = Field(..., description="User information")


class ProvidersResponse(BaseModel):
    """Response model for supported providers."""

    providers: list[str] = Field(..., description="List of supported OAuth providers")


class SuccessResponse(BaseModel):
    """Generic success response."""

    success: bool = Field(..., description="Whether operation was successful")
    message: str = Field(..., description="Success message")
