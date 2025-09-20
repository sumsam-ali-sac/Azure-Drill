"""
Common API response models.
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Any

class SuccessResponse(BaseModel):
    """Generic success response."""
    success: bool = Field(..., description="Whether operation was successful")
    message: str = Field(..., description="Success message")

class ErrorResponse(BaseModel):
    """Generic error response."""
    error: str = Field(..., description="Error type")
    message: str = Field(..., description="Error message")
    details: Optional[Any] = Field(None, description="Additional error details")

class HealthResponse(BaseModel):
    """Health check response."""
    status: str = Field(..., description="Service status")
    service: str = Field(..., description="Service name")
    features: List[str] = Field(..., description="Available features")
