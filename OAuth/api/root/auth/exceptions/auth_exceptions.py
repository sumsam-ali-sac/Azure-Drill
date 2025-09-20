"""
Custom exceptions for the authentication service.
"""

class AuthServiceError(Exception):
    """Base exception for all auth service errors."""
    
    def __init__(self, message: str, error_code: str = None):
        self.message = message
        self.error_code = error_code
        super().__init__(self.message)

class InvalidCredentialsError(AuthServiceError):
    """Raised when user provides invalid login credentials."""
    
    def __init__(self, message: str = "Invalid email or password"):
        super().__init__(message, "INVALID_CREDENTIALS")

class UserNotFoundError(AuthServiceError):
    """Raised when a user is not found in the system."""
    
    def __init__(self, message: str = "User not found"):
        super().__init__(message, "USER_NOT_FOUND")

class UserAlreadyExistsError(AuthServiceError):
    """Raised when attempting to create a user that already exists."""
    
    def __init__(self, message: str = "User already exists"):
        super().__init__(message, "USER_ALREADY_EXISTS")

class TokenExpiredError(AuthServiceError):
    """Raised when a token has expired."""
    
    def __init__(self, message: str = "Token has expired"):
        super().__init__(message, "TOKEN_EXPIRED")

class InvalidTokenError(AuthServiceError):
    """Raised when a token is invalid or malformed."""
    
    def __init__(self, message: str = "Invalid token"):
        super().__init__(message, "INVALID_TOKEN")

class InvalidOTPError(AuthServiceError):
    """Raised when OTP verification fails (for future OTP functionality)."""
    
    def __init__(self, message: str = "Invalid OTP code"):
        super().__init__(message, "INVALID_OTP")

class ProviderError(AuthServiceError):
    """Raised when OAuth provider operations fail."""
    
    def __init__(self, message: str, provider: str = None):
        self.provider = provider
        super().__init__(message, "PROVIDER_ERROR")

class ValidationError(AuthServiceError):
    """Raised when input validation fails."""
    
    def __init__(self, message: str, field: str = None):
        self.field = field
        super().__init__(message, "VALIDATION_ERROR")
