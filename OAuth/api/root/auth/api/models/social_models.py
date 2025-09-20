"""
Social authentication API request and response models.
"""

from pydantic import BaseModel, Field
from typing import Optional

class SocialAuthRequest(BaseModel):
    """Request model for social authentication."""
    provider: str = Field(..., description="OAuth provider name (google, azure)")
    auth_code: str = Field(..., description="Authorization code from provider")
    state: Optional[str] = Field(None, description="State parameter for CSRF protection")
    set_cookies: bool = Field(default=False, description="Whether to set authentication cookies")

class SocialAuthResponse(BaseModel):
    """Response model for social authentication."""
    user: dict = Field(..., description="User information")
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(..., description="Token type (bearer)")
    is_new_user: bool = Field(..., description="Whether this is a newly registered user")
