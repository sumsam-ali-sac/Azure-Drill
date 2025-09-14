"""
Shared constants for the authentication module.
Contains immutable values used across different components.
"""

from typing import List, Dict, Any

# JWT Algorithms
ALLOWED_JWT_ALGORITHMS: List[str] = ["HS256", "RS256", "ES256"]

# Token Types
TOKEN_TYPE_BEARER: str = "bearer"
TOKEN_TYPE_ACCESS: str = "access"
TOKEN_TYPE_REFRESH: str = "refresh"
TOKEN_TYPE_RESET: str = "reset"
TOKEN_TYPE_OTP: str = "otp"

# OAuth Providers
OAUTH_PROVIDER_GOOGLE: str = "google"
OAUTH_PROVIDER_AZURE: str = "azure"
SUPPORTED_OAUTH_PROVIDERS: List[str] = [OAUTH_PROVIDER_GOOGLE, OAUTH_PROVIDER_AZURE]

# OAuth Scopes
GOOGLE_OAUTH_SCOPES: List[str] = ["openid", "email", "profile"]
AZURE_OAUTH_SCOPES: List[str] = ["openid", "email", "profile"]

# OAuth URLs
GOOGLE_OAUTH_URLS: Dict[str, str] = {
    "authorize": "https://accounts.google.com/o/oauth2/v2/auth",
    "token": "https://oauth2.googleapis.com/token",
    "userinfo": "https://www.googleapis.com/oauth2/v2/userinfo",
    "jwks": "https://www.googleapis.com/oauth2/v3/certs"
}

AZURE_OAUTH_URLS: Dict[str, str] = {
    "authorize": "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize",
    "token": "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
    "userinfo": "https://graph.microsoft.com/v1.0/me",
    "jwks": "https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
}

# Security Constants
CSRF_STATE_KEY: str = "csrf_state"
CSRF_TOKEN_LENGTH: int = 32
OTP_SECRET_LENGTH: int = 32
PASSWORD_RESET_TOKEN_LENGTH: int = 32

# Password Requirements
PASSWORD_MIN_LENGTH: int = 12
PASSWORD_REQUIRE_UPPERCASE: bool = True
PASSWORD_REQUIRE_LOWERCASE: bool = True
PASSWORD_REQUIRE_DIGITS: bool = True
PASSWORD_REQUIRE_SPECIAL: bool = True
PASSWORD_SPECIAL_CHARS: str = "!@#$%^&*()_+-=[]{}|;:,.<>?"

# OTP Configuration
OTP_DIGITS: int = 6
OTP_INTERVAL: int = 30  # seconds
OTP_WINDOW: int = 1  # Allow 1 interval before/after current

# Rate Limiting Keys
RATE_LIMIT_KEY_LOGIN: str = "auth:login"
RATE_LIMIT_KEY_OTP: str = "auth:otp"
RATE_LIMIT_KEY_RESET: str = "auth:reset"
RATE_LIMIT_KEY_REFRESH: str = "auth:refresh"

# HTTP Status Codes
HTTP_200_OK: int = 200
HTTP_201_CREATED: int = 201
HTTP_400_BAD_REQUEST: int = 400
HTTP_401_UNAUTHORIZED: int = 401
HTTP_403_FORBIDDEN: int = 403
HTTP_404_NOT_FOUND: int = 404
HTTP_429_TOO_MANY_REQUESTS: int = 429
HTTP_500_INTERNAL_SERVER_ERROR: int = 500

# Default Roles
ROLE_USER: str = "user"
ROLE_ADMIN: str = "admin"
ROLE_MODERATOR: str = "moderator"
DEFAULT_ROLES: List[str] = [ROLE_USER]

# Permissions
PERMISSION_READ: str = "read"
PERMISSION_WRITE: str = "write"
PERMISSION_DELETE: str = "delete"
PERMISSION_ADMIN: str = "admin"

# Role-Permission Mapping
ROLE_PERMISSIONS: Dict[str, List[str]] = {
    ROLE_USER: [PERMISSION_READ],
    ROLE_MODERATOR: [PERMISSION_READ, PERMISSION_WRITE],
    ROLE_ADMIN: [PERMISSION_READ, PERMISSION_WRITE, PERMISSION_DELETE, PERMISSION_ADMIN]
}

# Email Templates
EMAIL_TEMPLATE_OTP: str = """
Subject: Your OTP Code - {app_name}

Hello,

Your one-time password (OTP) code is: {otp_code}

This code will expire in {expiry_minutes} minutes.

If you didn't request this code, please ignore this email.

Best regards,
{app_name} Team
"""

EMAIL_TEMPLATE_PASSWORD_RESET: str = """
Subject: Password Reset Request - {app_name}

Hello,

You have requested to reset your password. Click the link below to reset your password:

{reset_link}

This link will expire in {expiry_minutes} minutes.

If you didn't request this password reset, please ignore this email.

Best regards,
{app_name} Team
"""

EMAIL_TEMPLATE_WELCOME: str = """
Subject: Welcome to {app_name}!

Hello {user_name},

Welcome to {app_name}! Your account has been successfully created.

You can now log in using your credentials.

Best regards,
{app_name} Team
"""

# Cache Keys
CACHE_KEY_USER_ROLES: str = "user:roles:{user_id}"
CACHE_KEY_OTP_SECRET: str = "otp:secret:{user_id}"
CACHE_KEY_RATE_LIMIT: str = "rate_limit:{key}:{identifier}"

# Cache Expiry Times (in seconds)
CACHE_EXPIRY_USER_ROLES: int = 3600  # 1 hour
CACHE_EXPIRY_OTP_SECRET: int = 300   # 5 minutes
CACHE_EXPIRY_RATE_LIMIT: int = 3600  # 1 hour

# Regex Patterns
REGEX_EMAIL: str = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
REGEX_PASSWORD_STRENGTH: str = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]).{12,}$'
REGEX_UUID: str = r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'

# Error Messages
ERROR_INVALID_CREDENTIALS: str = "Invalid email or password"
ERROR_OTP_INVALID: str = "Invalid or expired OTP code"
ERROR_TOKEN_EXPIRED: str = "Token has expired"
ERROR_TOKEN_INVALID: str = "Invalid token"
ERROR_INSUFFICIENT_PERMISSIONS: str = "Insufficient permissions"
ERROR_RATE_LIMIT_EXCEEDED: str = "Rate limit exceeded. Please try again later"
ERROR_USER_NOT_FOUND: str = "User not found"
ERROR_EMAIL_ALREADY_EXISTS: str = "Email already exists"
ERROR_WEAK_PASSWORD: str = "Password does not meet security requirements"
ERROR_INVALID_EMAIL: str = "Invalid email format"
ERROR_OAUTH_ERROR: str = "OAuth authentication failed"
ERROR_CSRF_MISMATCH: str = "CSRF token mismatch"

# Success Messages
SUCCESS_LOGIN: str = "Login successful"
SUCCESS_LOGOUT: str = "Logout successful"
SUCCESS_REGISTRATION: str = "Registration successful"
SUCCESS_PASSWORD_RESET: str = "Password reset successful"
SUCCESS_OTP_SENT: str = "OTP code sent successfully"
SUCCESS_TOKEN_REFRESHED: str = "Token refreshed successfully"
