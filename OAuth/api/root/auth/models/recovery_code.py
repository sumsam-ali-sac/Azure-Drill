"""
Recovery Code model for account recovery codes.
"""

from datetime import datetime, timedelta
from typing import Optional, Literal
from pydantic import Field
from root.data.nosql.mongo.base_mongo_model import BaseMongoModel

# Type definition for recovery code types
RecoveryCodeType = Literal[
    "account_recovery", "password_reset", "otp_reset", "emergency_access"
]


class RecoveryCode(BaseMongoModel[str]):
    """
    Recovery Code model for storing account recovery codes.

    Recovery codes are longer-lived, single-use codes for account recovery
    when users lose access to their primary authentication methods.

    Inherits from BaseMongoModel[str] to get:
    - id: Optional[str] (UUID)
    - model_type: str (automatically set to 'RecoveryCode')
    - created_on: Optional[datetime]
    - updated_on: Optional[datetime]
    """

    user_id: str = Field(
        ..., description="ID of the user this recovery code belongs to"
    )
    code_hash: str = Field(..., description="Hashed recovery code for security")
    recovery_type: RecoveryCodeType = Field(
        ..., description="Type of recovery this code enables"
    )
    expiry: datetime = Field(..., description="When this recovery code expires")
    is_used: bool = Field(
        default=False, description="Whether this recovery code has been used"
    )
    used_at: Optional[datetime] = Field(
        None, description="When this recovery code was used"
    )
    used_ip: Optional[str] = Field(None, description="IP address where code was used")
    used_user_agent: Optional[str] = Field(
        None, description="User agent when code was used"
    )
    generated_by: Optional[str] = Field(
        None, description="Who/what generated this code"
    )
    metadata: dict = Field(
        default_factory=dict, description="Additional recovery metadata"
    )

    class Config:
        """Pydantic configuration."""

        json_encoders = {datetime: lambda v: v.isoformat() if v else None}
        json_schema_extra = {
            "example": {
                "user_id": "user-123-456",
                "code_hash": "$2b$12$hashed_recovery_code_here",
                "recovery_type": "account_recovery",
                "expiry": "2024-01-08T12:00:00Z",
                "is_used": False,
                "generated_by": "admin",
                "metadata": {
                    "reason": "User lost access to authenticator",
                    "approved_by": "support_agent_123",
                },
            }
        }

    def is_expired(self) -> bool:
        """Check if the recovery code has expired."""
        return datetime.utcnow() > self.expiry

    def is_valid(self) -> bool:
        """Check if the recovery code is valid (not used and not expired)."""
        return not self.is_used and not self.is_expired()

    def mark_as_used(
        self, ip_address: Optional[str] = None, user_agent: Optional[str] = None
    ) -> None:
        """
        Mark the recovery code as used.

        Args:
            ip_address: IP address where the code was used
            user_agent: User agent string where the code was used
        """
        self.is_used = True
        self.used_at = datetime.utcnow()
        self.used_ip = ip_address
        self.used_user_agent = user_agent
        self.update_timestamp()

    def get_time_until_expiry(self) -> timedelta:
        """Get the time remaining until expiry."""
        if self.is_expired():
            return timedelta(0)
        return self.expiry - datetime.utcnow()

    def get_usage_info(self) -> dict:
        """Get information about when and where this code was used."""
        if not self.is_used:
            return {"used": False}

        return {
            "used": True,
            "used_at": self.used_at,
            "used_ip": self.used_ip,
            "used_user_agent": self.used_user_agent,
        }

    def extend_expiry(self, hours: int = 24) -> None:
        """Extend the expiry time of the recovery code."""
        if not self.is_used:
            self.expiry = datetime.utcnow() + timedelta(hours=hours)
            self.update_timestamp()

    @classmethod
    def create_account_recovery_code(
        cls,
        user_id: str,
        code_hash: str,
        expiry_days: int = 7,
        generated_by: Optional[str] = None,
    ) -> "RecoveryCode":
        """Create an account recovery code."""
        return cls(
            user_id=user_id,
            code_hash=code_hash,
            recovery_type="account_recovery",
            expiry=datetime.utcnow() + timedelta(days=expiry_days),
            generated_by=generated_by,
        )

    @classmethod
    def create_password_reset_code(
        cls, user_id: str, code_hash: str, expiry_hours: int = 24
    ) -> "RecoveryCode":
        """Create a password reset recovery code."""
        return cls(
            user_id=user_id,
            code_hash=code_hash,
            recovery_type="password_reset",
            expiry=datetime.utcnow() + timedelta(hours=expiry_hours),
        )

    @classmethod
    def create_otp_reset_code(
        cls, user_id: str, code_hash: str, expiry_hours: int = 48
    ) -> "RecoveryCode":
        """Create an OTP reset recovery code."""
        return cls(
            user_id=user_id,
            code_hash=code_hash,
            recovery_type="otp_reset",
            expiry=datetime.utcnow() + timedelta(hours=expiry_hours),
        )

    @classmethod
    def create_emergency_access_code(
        cls,
        user_id: str,
        code_hash: str,
        expiry_hours: int = 1,
        generated_by: Optional[str] = None,
    ) -> "RecoveryCode":
        """Create an emergency access code (short-lived)."""
        return cls(
            user_id=user_id,
            code_hash=code_hash,
            recovery_type="emergency_access",
            expiry=datetime.utcnow() + timedelta(hours=expiry_hours),
            generated_by=generated_by,
        )
