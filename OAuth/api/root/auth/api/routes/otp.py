"""
OTP authentication API routes.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from auth_service.services.otp_service import OTPService
from auth_service.api.dependencies import get_otp_service, get_current_user
from auth_service.models.user import User
from auth_service.exceptions.auth_exceptions import ValidationError, OTPError, InvalidCredentialsError

router = APIRouter()

# Request/Response models
class OTPSetupRequest(BaseModel):
    """Request model for OTP setup."""
    pass  # No additional data needed, user comes from auth

class OTPSetupResponse(BaseModel):
    """Response model for OTP setup."""
    secret: str = Field(..., description="OTP secret (for manual entry)")
    qr_code_uri: str = Field(..., description="TOTP URI for QR code")
    qr_code_data: str = Field(..., description="Base64 encoded QR code image")
    backup_codes: list[str] = Field(..., description="Backup codes for recovery")
    setup_complete: bool = Field(..., description="Whether setup is complete")

class OTPVerifySetupRequest(BaseModel):
    """Request model for OTP setup verification."""
    otp_code: str = Field(..., description="OTP code from authenticator app", min_length=6, max_length=6)

class OTPVerifyRequest(BaseModel):
    """Request model for OTP verification."""
    otp_code: str = Field(..., description="OTP code to verify", min_length=6, max_length=8)

class OTPAuthRequest(BaseModel):
    """Request model for OTP authentication."""
    user_id: str = Field(..., description="User ID for OTP authentication")
    otp_code: str = Field(..., description="OTP code for authentication", min_length=6, max_length=8)
    set_cookies: bool = Field(default=False, description="Whether to set authentication cookies")

class OTPStatusResponse(BaseModel):
    """Response model for OTP status."""
    enabled: bool = Field(..., description="Whether OTP is enabled")
    configured: bool = Field(..., description="Whether OTP is configured")
    issuer: str = Field(..., description="OTP issuer name")

class BackupCodesResponse(BaseModel):
    """Response model for backup codes."""
    backup_codes: list[str] = Field(..., description="Generated backup codes")

class RecoveryCodesResponse(BaseModel):
    """Response model for recovery codes."""
    recovery_codes: list[str] = Field(..., description="Generated recovery codes")

class SuccessResponse(BaseModel):
    """Generic success response."""
    success: bool = Field(..., description="Whether operation was successful")
    message: str = Field(..., description="Success message")

@router.post("/setup", response_model=OTPSetupResponse)
async def setup_otp(
    request: OTPSetupRequest,
    current_user: User = Depends(get_current_user),
    otp_service: OTPService = Depends(get_otp_service)
):
    """
    Set up TOTP (Time-based One-Time Password) for the authenticated user.
    
    Returns QR code and backup codes for the user to configure their authenticator app.
    """
    try:
        result = await otp_service.setup_totp_async(current_user.id)
        return OTPSetupResponse(**result)
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="OTP setup failed")

@router.post("/setup/verify", response_model=SuccessResponse)
async def verify_otp_setup(
    request: OTPVerifySetupRequest,
    current_user: User = Depends(get_current_user),
    otp_service: OTPService = Depends(get_otp_service)
):
    """
    Verify OTP setup by validating the first OTP code from the authenticator app.
    
    This completes the OTP setup process and enables OTP for the user.
    """
    try:
        success = await otp_service.verify_totp_setup_async(current_user.id, request.otp_code)
        if success:
            return SuccessResponse(success=True, message="OTP setup verified successfully")
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid OTP code")
    except OTPError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="OTP verification failed")

@router.post("/verify", response_model=SuccessResponse)
async def verify_otp(
    request: OTPVerifyRequest,
    current_user: User = Depends(get_current_user),
    otp_service: OTPService = Depends(get_otp_service)
):
    """
    Verify an OTP code for the authenticated user.
    
    Can be used to verify TOTP codes or backup codes.
    """
    try:
        is_valid = await otp_service.verify_otp_async(current_user.id, request.otp_code)
        if is_valid:
            return SuccessResponse(success=True, message="OTP code verified successfully")
        else:
            return SuccessResponse(success=False, message="Invalid OTP code")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="OTP verification failed")

@router.post("/authenticate")
async def authenticate_with_otp(
    request: OTPAuthRequest,
    http_request: Request,
    otp_service: OTPService = Depends(get_otp_service)
):
    """
    Authenticate a user using OTP code (typically as second factor).
    
    Returns authentication tokens if OTP is valid.
    """
    try:
        credentials = {
            "user_id": request.user_id,
            "otp_code": request.otp_code
        }
        
        result = await otp_service.authenticate_async(credentials, request.set_cookies)
        
        # If cookies are requested, return the Response object
        if request.set_cookies:
            return result
        
        return result
        
    except InvalidCredentialsError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="OTP authentication failed")

@router.get("/status", response_model=OTPStatusResponse)
async def get_otp_status(
    current_user: User = Depends(get_current_user),
    otp_service: OTPService = Depends(get_otp_service)
):
    """
    Get OTP status for the authenticated user.
    
    Returns whether OTP is enabled and configured.
    """
    try:
        status_info = await otp_service.get_otp_status_async(current_user.id)
        return OTPStatusResponse(**status_info)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to get OTP status")

@router.delete("/disable", response_model=SuccessResponse)
async def disable_otp(
    current_user: User = Depends(get_current_user),
    otp_service: OTPService = Depends(get_otp_service)
):
    """
    Disable OTP for the authenticated user.
    
    This removes OTP protection from the user's account.
    """
    try:
        success = await otp_service.disable_otp_async(current_user.id)
        if success:
            return SuccessResponse(success=True, message="OTP disabled successfully")
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Failed to disable OTP")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to disable OTP")

@router.post("/backup-codes", response_model=BackupCodesResponse)
async def generate_backup_codes(
    current_user: User = Depends(get_current_user),
    otp_service: OTPService = Depends(get_otp_service)
):
    """
    Generate new backup codes for the authenticated user.
    
    Backup codes can be used when the user doesn't have access to their authenticator app.
    """
    try:
        backup_codes = await otp_service.regenerate_backup_codes_async(current_user.id)
        return BackupCodesResponse(backup_codes=backup_codes)
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to generate backup codes")

@router.post("/recovery-codes", response_model=RecoveryCodesResponse)
async def generate_recovery_codes(
    current_user: User = Depends(get_current_user),
    otp_service: OTPService = Depends(get_otp_service)
):
    """
    Generate recovery codes for account recovery.
    
    Recovery codes are longer-lived codes for account recovery scenarios.
    """
    try:
        recovery_codes = await otp_service.generate_recovery_codes_async(current_user.id)
        return RecoveryCodesResponse(recovery_codes=recovery_codes)
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to generate recovery codes")

# Health check endpoint for OTP service
@router.get("/health")
async def otp_health_check():
    """Health check for OTP service."""
    return {
        "status": "healthy",
        "service": "otp-authentication",
        "features": [
            "TOTP setup and verification",
            "Backup codes",
            "Recovery codes",
            "QR code generation"
        ]
    }
