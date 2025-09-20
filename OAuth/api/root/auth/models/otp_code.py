"""
OTP Code model for temporary one-time password codes.
"""

from datetime import datetime, timedelta
from typing import Optional, Literal
from pydantic import Field
from root.data.nosql.mongo import BaseMongoModel

OTPCodeType = Literal["setup", "login", "recovery", "backup"]


class OTPCode(BaseMongoModel[str]):
    """
    OTP Code model for storing temporary one-time password codes.

    Used for:
    - Setup verification codes during TOTP setup
    - Login verification codes for authentication
    - Recovery codes for account recovery
    - Backup codes for emergency access

    Inherits from BaseMongoModel[str] to get:
    - id: Optional[str] (UUID)
    - model_type: str (automatically set to 'OTPCode')
    - created_on: Optional[datetime]
    - updated_on: Optional[datetime]
    """

    user_id: str = Field(..., description="ID of the user this OTP code belongs to")
    code_hash: str = Field(..., description="Hashed OTP code for security")
    code_type: OTPCodeType = Field(..., description="Type of OTP code")
    expiry: datetime = Field(..., description="When this OTP code expires")
    is_used: bool = Field(default=False, description="Whether this code has been used")
    used_at: Optional[datetime] = Field(None, description="When this code was used")
    attempts: int = Field(default=0, description="Number of verification attempts")
    max_attempts: int = Field(default=3, description="Maximum allowed attempts")
    metadata: dict = Field(
        default_factory=dict, description="Additional metadata for the code"
    )

    class Config:
        """Pydantic configuration."""

        json_encoders = {datetime: lambda v: v.isoformat() if v else None}
        schema_extra = {
            "example": {
                "user_id": "user-123-456",
                "code_hash": "$2b$12$hashed_otp_code_here",
                "code_type": "setup",
                "expiry": "2024-01-01T12:00:00Z",
                "is_used": False,
                "attempts": 0,
                "max_attempts": 3,
                "metadata": {
                    "ip_address": "192.168.1.1",
                    "user_agent": "Mozilla/5.0...",
                },
            }
        }

    def is_expired(self) -> bool:
        """Check if the OTP code has expired."""
        return datetime.utcnow() > self.expiry

    def is_valid(self) -> bool:
        """Check if the OTP code is valid (not used, not expired, attempts not exceeded)."""
        return (
            not self.is_used
            and not self.is_expired()
            and self.attempts < self.max_attempts
        )

    def increment_attempts(self) -> None:
        """Increment the number of verification attempts."""
        self.attempts += 1
        self.update_timestamp()

    def mark_as_used(self) -> None:
        """Mark the OTP code as used."""
        self.is_used = True
        self.used_at = datetime.utcnow()
        self.update_timestamp()

    def get_remaining_attempts(self) -> int:
        """Get the number of remaining verification attempts."""
        return max(0, self.max_attempts - self.attempts)

    def get_time_until_expiry(self) -> timedelta:
        """Get the time remaining until expiry."""
        if self.is_expired():
            return timedelta(0)
        return self.expiry - datetime.utcnow()

    @classmethod
    def create_setup_code(
        cls, user_id: str, code_hash: str, expiry_minutes: int = 15
    ) -> "OTPCode":
        """Create a setup verification code."""
        return cls(
            user_id=user_id,
            code_hash=code_hash,
            code_type="setup",
            expiry=datetime.utcnow() + timedelta(minutes=expiry_minutes),
            max_attempts=5,  # More attempts for setup
        )

    @classmethod
    def create_login_code(
        cls, user_id: str, code_hash: str, expiry_minutes: int = 5
    ) -> "OTPCode":
        """Create a login verification code."""
        return cls(
            user_id=user_id,
            code_hash=code_hash,
            code_type="login",
            expiry=datetime.utcnow() + timedelta(minutes=expiry_minutes),
            max_attempts=3,
        )

    @classmethod
    def create_recovery_code(
        cls, user_id: str, code_hash: str, expiry_hours: int = 24
    ) -> "OTPCode":
        """Create a recovery code."""
        return cls(
            user_id=user_id,
            code_hash=code_hash,
            code_type="recovery",
            expiry=datetime.utcnow() + timedelta(hours=expiry_hours),
            max_attempts=1,  # Recovery codes are single-use
        )
