"""
User model inheriting from BaseMongoModel.
"""

from datetime import datetime
from typing import Optional, Dict
from pydantic import Field, EmailStr
from root.data.nosql.mongo import BaseMongoModel


class User(BaseMongoModel[str]):
    """
    User model for authentication system.

    Inherits from BaseMongoModel[str] to get:
    - id: Optional[str] (UUID)
    - model_type: str (automatically set to 'User')
    - created_on: Optional[datetime]
    - updated_on: Optional[datetime]
    """

    email: EmailStr = Field(..., description="User's email address")
    hashed_password: Optional[str] = Field(
        None, description="Hashed password for email/password auth"
    )
    social_ids: Dict[str, str] = Field(
        default_factory=dict, description="Social provider IDs (provider:user_id)"
    )
    is_active: bool = Field(
        default=True, description="Whether the user account is active"
    )
    first_name: Optional[str] = Field(None, description="User's first name")
    last_name: Optional[str] = Field(None, description="User's last name")

    # Future OTP support
    otp_secret: Optional[str] = Field(
        None, description="OTP secret for TOTP (future use)"
    )
    otp_expiry: Optional[datetime] = Field(
        None, description="OTP expiry time (future use)"
    )

    class Config:
        """Pydantic configuration."""

        json_encoders = {datetime: lambda v: v.isoformat()}
        schema_extra = {
            "example": {
                "email": "user@example.com",
                "is_active": True,
                "first_name": "John",
                "last_name": "Doe",
                "social_ids": {
                    "google": "google_user_id_123",
                    "azure": "azure_user_id_456",
                },
            }
        }

    def get_full_name(self) -> str:
        """Get user's full name."""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        return self.first_name or self.last_name or self.email

    def has_social_provider(self, provider: str) -> bool:
        """Check if user has a specific social provider linked."""
        return provider in self.social_ids

    def add_social_provider(self, provider: str, provider_user_id: str) -> None:
        """Add a social provider to the user."""
        self.social_ids[provider] = provider_user_id

    def remove_social_provider(self, provider: str) -> None:
        """Remove a social provider from the user."""
        self.social_ids.pop(provider, None)
