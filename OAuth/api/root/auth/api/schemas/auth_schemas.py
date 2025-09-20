"""
Authentication API schemas.
"""

from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, EmailStr
from .common_schemas import BaseResponse

class RegisterRequest(BaseModel):
    """User registration request."""
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=8, description="User password")
    first_name: Optional[str] = Field(None, max_length=50, description="First name")
    last_name: Optional[str] = Field(None, max_length=50, description="Last name")

class LoginRequest(BaseModel):
    """User login request."""
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., description="User password")
    remember_me: bool = Field(default=False, description="Extended session duration")

class ChangePasswordRequest(BaseModel):
    """Change password request."""
    current_password: str = Field(..., description="Current password")
    new_password: str = Field(..., min_length=8, description="New password")

class ResetPasswordRequest(BaseModel):
    """Password reset request."""
    email: EmailStr = Field(..., description="User email address")

class ConfirmResetRequest(BaseModel):
    """Confirm password reset request."""
    reset_token: str = Field(..., description="Password reset token")
    new_password: str = Field(..., min_length=8, description="New password")

class TokenResponse(BaseResponse):
    """Authentication token response."""
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiration in seconds")

class UserResponse(BaseModel):
    """User information response."""
    id: str = Field(..., description="User ID")
    email: str = Field(..., description="User email")
    first_name: Optional[str] = Field(None, description="First name")
    last_name: Optional[str] = Field(None, description="Last name")
    is_active: bool = Field(..., description="Whether user is active")
    created_on: str = Field(..., description="Creation timestamp")
    social_providers: list[str] = Field(default_factory=list, description="Connected social providers")
