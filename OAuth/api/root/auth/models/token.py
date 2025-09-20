"""
Token model for JWT token management.
"""

from datetime import datetime
from typing import Literal
from pydantic import Field
from root.data.nosql.mongo.base_mongo_model import BaseMongoModel

TokenType = Literal['access', 'refresh']

class Token(BaseMongoModel[str]):
    """
    Token model for JWT token storage and management.
    
    Inherits from BaseMongoModel[str] to get:
    - id: Optional[str] (UUID)
    - model_type: str (automatically set to 'Token')
    - created_on: Optional[datetime]
    - updated_on: Optional[datetime]
    """
    
    user_id: str = Field(..., description="ID of the user this token belongs to")
    token: str = Field(..., description="The JWT token string")
    type: TokenType = Field(..., description="Token type: access or refresh")
    expiry: datetime = Field(..., description="When the token expires")
    is_revoked: bool = Field(default=False, description="Whether the token has been revoked")
    
    class Config:
        """Pydantic configuration."""
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
        schema_extra = {
            "example": {
                "user_id": "user_uuid_123",
                "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
                "type": "access",
                "expiry": "2024-01-01T12:00:00Z",
                "is_revoked": False
            }
        }
    
    def is_expired(self) -> bool:
        """Check if the token is expired."""
        return datetime.utcnow() > self.expiry
    
    def is_valid(self) -> bool:
        """Check if the token is valid (not expired and not revoked)."""
        return not self.is_expired() and not self.is_revoked
    
    def revoke(self) -> None:
        """Revoke the token."""
        self.is_revoked = True
