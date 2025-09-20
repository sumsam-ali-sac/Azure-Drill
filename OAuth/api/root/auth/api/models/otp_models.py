"""
OTP API request and response models.
"""

from pydantic import BaseModel, Field
from typing import List, Optional

class OTPSetupRequest(BaseModel):
    """Request model for OTP setup."""
    password: str = Field(..., description="User's password for verification")

class OTPVerifyRequest(BaseModel):
    """Request model for OTP verification."""
    otp_code: str = Field(..., description="6-digit OTP code", min_length=6, max_length=6)

class OTPDisableRequest(BaseModel):
    """Request model for disabling OTP."""
    password: str = Field(..., description="User's password for verification")
    otp_code: Optional[str] = Field(None, description="Current OTP code (if available)")

class BackupCodeVerifyRequest(BaseModel):
    """Request model for backup code verification."""
    backup_code: str = Field(..., description="8-character backup code")

class OTPSetupResponse(BaseModel):
    """Response model for OTP setup."""
    secret: str = Field(..., description="TOTP secret key")
    qr_code: str = Field(..., description="Base64 encoded QR code image")
    backup_codes: List[str] = Field(..., description="List of backup codes")

class BackupCodesResponse(BaseModel):
    """Response model for backup codes."""
    backup_codes: List[str] = Field(..., description="List of backup codes")

class OTPStatusResponse(BaseModel):
    """Response model for OTP status."""
    enabled: bool = Field(..., description="Whether OTP is enabled")
    backup_codes_remaining: int = Field(..., description="Number of unused backup codes")
