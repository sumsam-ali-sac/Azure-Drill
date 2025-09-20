"""
Common API schemas used across multiple endpoints.
"""

from typing import Optional, Dict, Any
from pydantic import BaseModel, Field

class BaseResponse(BaseModel):
    """Base response model for all API responses."""
    success: bool = Field(..., description="Whether the operation was successful")
    message: str = Field(..., description="Human-readable message")
    data: Optional[Dict[str, Any]] = Field(None, description="Response data")
    errors: Optional[Dict[str, Any]] = Field(None, description="Error details")

class ErrorResponse(BaseModel):
    """Error response model."""
    success: bool = Field(False, description="Always false for errors")
    message: str = Field(..., description="Error message")
    error_code: Optional[str] = Field(None, description="Machine-readable error code")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional error details")

class PaginationParams(BaseModel):
    """Pagination parameters for list endpoints."""
    limit: int = Field(default=20, ge=1, le=100, description="Number of items per page")
    skip: int = Field(default=0, ge=0, description="Number of items to skip")

class PaginatedResponse(BaseResponse):
    """Paginated response model."""
    total: int = Field(..., description="Total number of items")
    limit: int = Field(..., description="Items per page")
    skip: int = Field(..., description="Items skipped")
    has_more: bool = Field(..., description="Whether there are more items")
