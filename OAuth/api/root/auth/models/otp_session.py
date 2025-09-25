"""
OTP Session model for tracking OTP authentication sessions.
"""

from datetime import datetime, timedelta
from typing import Optional, Literal
from pydantic import Field
from root.data.nosql.mongo.base_mongo_model import BaseMongoModel

# Type definition for OTP session states
OTPSessionState = Literal["pending", "verified", "expired", "failed", "cancelled"]


class OTPSession(BaseMongoModel[str]):
    """
    OTP Session model for tracking multi-step OTP authentication flows.

    Used to track the state of OTP authentication sessions, especially
    for multi-factor authentication flows where OTP is the second factor.

    Inherits from BaseMongoModel[str] to get:
    - id: Optional[str] (UUID)
    - model_type: str (automatically set to 'OTPSession')
    - created_on: Optional[datetime]
    - updated_on: Optional[datetime]
    """

    user_id: str = Field(..., description="ID of the user this session belongs to")
    session_token: str = Field(
        ..., description="Unique session token for this OTP session"
    )
    state: OTPSessionState = Field(
        default="pending", description="Current state of the OTP session"
    )
    expiry: datetime = Field(..., description="When this OTP session expires")
    ip_address: Optional[str] = Field(None, description="IP address of the client")
    user_agent: Optional[str] = Field(None, description="User agent of the client")
    attempts: int = Field(default=0, description="Number of OTP verification attempts")
    max_attempts: int = Field(default=3, description="Maximum allowed attempts")
    verified_at: Optional[datetime] = Field(
        None, description="When the OTP was successfully verified"
    )
    failed_at: Optional[datetime] = Field(None, description="When the session failed")
    metadata: dict = Field(
        default_factory=dict, description="Additional session metadata"
    )

    class Config:
        """Pydantic configuration."""

        json_encoders = {datetime: lambda v: v.isoformat() if v else None}
        json_schema_extra = {
            "example": {
                "user_id": "user-123-456",
                "session_token": "otp_session_abc123def456",
                "state": "pending",
                "expiry": "2024-01-01T12:15:00Z",
                "ip_address": "192.168.1.1",
                "user_agent": "Mozilla/5.0...",
                "attempts": 0,
                "max_attempts": 3,
                "metadata": {"auth_method": "email_password", "requires_otp": True},
            }
        }

    def is_expired(self) -> bool:
        """Check if the OTP session has expired."""
        return datetime.utcnow() > self.expiry

    def is_active(self) -> bool:
        """Check if the OTP session is active (pending and not expired)."""
        return self.state == "pending" and not self.is_expired()

    def is_verified(self) -> bool:
        """Check if the OTP session has been verified."""
        return self.state == "verified"

    def can_attempt(self) -> bool:
        """Check if more OTP attempts are allowed."""
        return self.is_active() and self.attempts < self.max_attempts

    def increment_attempts(self) -> None:
        """Increment the number of OTP attempts."""
        self.attempts += 1
        self.update_timestamp()

        # Auto-fail if max attempts reached
        if self.attempts >= self.max_attempts:
            self.mark_as_failed()

    def mark_as_verified(self) -> None:
        """Mark the OTP session as verified."""
        self.state = "verified"
        self.verified_at = datetime.utcnow()
        self.update_timestamp()

    def mark_as_failed(self) -> None:
        """Mark the OTP session as failed."""
        self.state = "failed"
        self.failed_at = datetime.utcnow()
        self.update_timestamp()

    def mark_as_cancelled(self) -> None:
        """Mark the OTP session as cancelled."""
        self.state = "cancelled"
        self.update_timestamp()

    def extend_expiry(self, minutes: int = 5) -> None:
        """Extend the session expiry time."""
        if self.is_active():
            self.expiry = datetime.utcnow() + timedelta(minutes=minutes)
            self.update_timestamp()

    def get_remaining_attempts(self) -> int:
        """Get the number of remaining OTP attempts."""
        return max(0, self.max_attempts - self.attempts)

    def get_time_until_expiry(self) -> timedelta:
        """Get the time remaining until expiry."""
        if self.is_expired():
            return timedelta(0)
        return self.expiry - datetime.utcnow()

    def get_session_info(self) -> dict:
        """Get comprehensive session information."""
        return {
            "session_id": self.id,
            "user_id": self.user_id,
            "state": self.state,
            "is_active": self.is_active(),
            "is_verified": self.is_verified(),
            "attempts": self.attempts,
            "remaining_attempts": self.get_remaining_attempts(),
            "time_until_expiry": self.get_time_until_expiry().total_seconds(),
            "created_at": self.created_on,
            "verified_at": self.verified_at,
            "failed_at": self.failed_at,
        }

    @classmethod
    def create_session(
        cls,
        user_id: str,
        session_token: str,
        expiry_minutes: int = 15,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        max_attempts: int = 3,
    ) -> "OTPSession":
        """Create a new OTP session."""
        return cls(
            user_id=user_id,
            session_token=session_token,
            expiry=datetime.utcnow() + timedelta(minutes=expiry_minutes),
            ip_address=ip_address,
            user_agent=user_agent,
            max_attempts=max_attempts,
        )
