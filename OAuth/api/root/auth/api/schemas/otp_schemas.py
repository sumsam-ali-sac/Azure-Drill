"""
OTP API schemas.
"""

from typing import Optional, List
from pydantic import BaseModel, Field
from .common_schemas import BaseResponse

class SetupOTPRequest(BaseModel):
    """Setup OTP request."""
    user_id: Optional[str] = Field(None, description="User ID (optional if authenticated)")

class VerifyOTPSetupRequest(BaseModel):
    """Verify OTP setup request."""
    user_id: Optional[str] = Field(None, description="User ID (optional if authenticated)")
    otp_code: str = Field(..., min_length=6, max_length=6, description="6-digit OTP code")

class VerifyOTPRequest(BaseModel):
    """Verify OTP request."""
    user_id: Optional[str] = Field(None, description="User ID (optional if authenticated)")
    otp_code: str = Field(..., min_length=6, max_length=8, description="OTP code or backup code")

class DisableOTPRequest(BaseModel):
    """Disable OTP request."""
    user_id: Optional[str] = Field(None, description="User ID (optional if authenticated)")
    confirmation: bool = Field(..., description="Confirmation that user wants to disable OTP")

class OTPSetupResponse(BaseResponse):
    """OTP setup response."""
    secret: str = Field(..., description="TOTP secret key")
    qr_code_url: str = Field(..., description="QR code URL for authenticator apps")
    backup_codes: List[str] = Field(..., description="Backup codes for recovery")

class OTPStatusResponse(BaseResponse):
    """OTP status response."""
    enabled: bool = Field(..., description="Whether OTP is enabled")
    verified: bool = Field(..., description="Whether OTP setup is verified")
    backup_codes_count: int = Field(..., description="Number of unused backup codes")

class BackupCodesResponse(BaseResponse):
    """Backup codes response."""
    backup_codes: List[str] = Field(..., description="New backup codes")
