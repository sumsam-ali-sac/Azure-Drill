"""
Backup Code model for OTP backup codes.
"""

from datetime import datetime
from typing import Optional
from pydantic import Field
from root.data.nosql.mongo.base_mongo_model import BaseMongoModel


class BackupCode(BaseMongoModel[str]):
    """
    Backup Code model for storing OTP backup codes.

    Backup codes are single-use codes that can be used when the user
    doesn't have access to their authenticator app.

    Inherits from BaseMongoModel[str] to get:
    - id: Optional[str] (UUID)
    - model_type: str (automatically set to 'BackupCode')
    - created_on: Optional[datetime]
    - updated_on: Optional[datetime]
    """

    user_id: str = Field(..., description="ID of the user this backup code belongs to")
    code_hash: str = Field(..., description="Hashed backup code for security")
    is_used: bool = Field(
        default=False, description="Whether this backup code has been used"
    )
    used_at: Optional[datetime] = Field(
        None, description="When this backup code was used"
    )
    used_ip: Optional[str] = Field(None, description="IP address where code was used")
    used_user_agent: Optional[str] = Field(
        None, description="User agent when code was used"
    )
    code_set_id: Optional[str] = Field(
        None, description="ID of the backup code set this belongs to"
    )

    class Config:
        """Pydantic configuration."""

        json_encoders = {datetime: lambda v: v.isoformat() if v else None}
        json_schema_extra = {
            "example": {
                "user_id": "user-123-456",
                "code_hash": "$2b$12$hashed_backup_code_here",
                "is_used": False,
                "code_set_id": "backup-set-789",
            }
        }

    def is_valid(self) -> bool:
        """Check if the backup code is valid (not used)."""
        return not self.is_used

    def mark_as_used(
        self, ip_address: Optional[str] = None, user_agent: Optional[str] = None
    ) -> None:
        """
        Mark the backup code as used.

        Args:
            ip_address: IP address where the code was used
            user_agent: User agent string where the code was used
        """
        self.is_used = True
        self.used_at = datetime.utcnow()
        self.used_ip = ip_address
        self.used_user_agent = user_agent
        self.update_timestamp()

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

    @classmethod
    def create_backup_code(
        cls, user_id: str, code_hash: str, code_set_id: Optional[str] = None
    ) -> "BackupCode":
        """Create a new backup code."""
        return cls(user_id=user_id, code_hash=code_hash, code_set_id=code_set_id)
