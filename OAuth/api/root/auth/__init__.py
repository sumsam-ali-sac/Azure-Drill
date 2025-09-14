"""
Advanced Authentication Module for FastAPI Applications

This module provides a comprehensive authentication and authorization system with:
- JWT token management (HS256/RS256/ES256)
- Social OAuth (Google, Azure)
- OTP/2FA support
- RBAC (Role-Based Access Control)
- Rate limiting and security features
- Password management with Argon2
- Stateless design for scalability
"""

from auth.configs import config
from auth.core.auth_manager import AuthManager
from auth.exceptions import (
    InvalidCredentialsError,
    OTPInvalidError,
    TokenExpiredError,
    RateLimitExceededError,
    InsufficientPermissionsError,
    UserNotFoundError,
    AccountLockedError
)
from auth.middleware import auth_dependency, require_roles
from auth.security.token_utils import TokenManager
from auth.oauth.oauth_manager import OAuthManager
from auth.schemas import (
    UserIn,
    TokenResponse,
    ResetRequest,
    OTPRequest,
    SocialLoginRequest,
    UserProfile
)

__version__ = "2.0.0"
__author__ = "Advanced Auth Module"

# Main auth manager instance
auth_manager = AuthManager()

__all__ = [
    "config",
    "auth_manager",
    "AuthManager",
    "InvalidCredentialsError",
    "OTPInvalidError", 
    "TokenExpiredError",
    "RateLimitExceededError",
    "InsufficientPermissionsError",
    "UserNotFoundError",
    "AccountLockedError",
    "auth_dependency",
    "require_roles",
    "TokenManager",
    "OAuthManager",
    "UserIn",
    "TokenResponse",
    "ResetRequest",
    "OTPRequest",
    "SocialLoginRequest",
    "UserProfile"
]
