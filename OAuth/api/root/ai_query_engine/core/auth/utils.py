"""
Refactored to use absolute imports and removed multiple classes
Updated to import individual utility classes from their dedicated modules.
"""

# Import all utility classes from their dedicated modules
from auth.email.email_manager import EmailManager
from auth.rate_limiting.rate_limiter import RateLimiter
from auth.csrf.csrf_manager import CSRFManager
from auth.security.security_utils import SecurityUtils
from auth.validation.validation_utils import ValidationUtils

# Global utility instances for backward compatibility
email_manager = EmailManager()
rate_limiter = RateLimiter()
csrf_manager = CSRFManager()
security_utils = SecurityUtils()
validation_utils = ValidationUtils()

__all__ = [
    'EmailManager',
    'RateLimiter', 
    'CSRFManager',
    'SecurityUtils',
    'ValidationUtils',
    'email_manager',
    'rate_limiter',
    'csrf_manager',
    'security_utils',
    'validation_utils'
]
