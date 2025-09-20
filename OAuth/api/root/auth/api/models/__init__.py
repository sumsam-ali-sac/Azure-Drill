"""
API request and response models.
"""

from .auth_models import *
from .otp_models import *
from .social_models import *
from .common_models import *

__all__ = [
    # Auth models
    "LoginRequest",
    "RegisterRequest", 
    "ChangePasswordRequest",
    "PasswordResetRequest",
    "PasswordResetConfirmRequest",
    "LogoutRequest",
    "AuthResponse",
    "UserResponse",
    
    # OTP models
    "OTPSetupRequest",
    "OTPVerifyRequest",
    "OTPSetupResponse",
    "BackupCodesResponse",
    
    # Social models
    "SocialAuthRequest",
    "SocialAuthResponse",
    
    # Common models
    "SuccessResponse",
    "ErrorResponse",
    "HealthResponse"
]
