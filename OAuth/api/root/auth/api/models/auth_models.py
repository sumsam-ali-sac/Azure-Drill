"""
Authentication API request and response models.
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional

class LoginRequest(BaseModel):
    """Request model for user login."""
    email: EmailStr = Field(..., description="User's email address")
    password: str = Field(..., description="User's password", min_length=8)
    set_cookies: bool = Field(default=False, description="Whether to set authentication cookies")

class RegisterRequest(BaseModel):
    """Request model for user registration."""
    email: EmailStr = Field(..., description="User's email address")
    password: str = Field(..., description="User's password", min_length=8)
    first_name: Optional[str] = Field(None, description="User's first name")
    last_name: Optional[str] = Field(None, description="User's last name")

class ChangePasswordRequest(BaseModel):
    """Request model for password change."""
    old_password: str = Field(..., description="Current password")
    new_password: str = Field(..., description="New password", min_length=8)

class PasswordResetRequest(BaseModel):
    """Request model for password reset initiation."""
    email: EmailStr = Field(..., description="User's email address")

class PasswordResetConfirmRequest(BaseModel):
    """Request model for password reset confirmation."""
    reset_token: str = Field(..., description="Password reset token")
    new_password: str = Field(..., description="New password", min_length=8)

class LogoutRequest(BaseModel):
    """Request model for logout."""
    clear_cookies: bool = Field(default=False, description="Whether to clear authentication cookies")

class AuthResponse(BaseModel):
    """Response model for authentication."""
    user: dict = Field(..., description="User information")
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(..., description="Token type (bearer)")

class UserResponse(BaseModel):
    """Response model for user information."""
    user: dict = Field(..., description="User information")
