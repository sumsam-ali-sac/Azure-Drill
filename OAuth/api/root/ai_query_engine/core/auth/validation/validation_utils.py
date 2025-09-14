"""
Input validation utilities.
Provides validation functions for common input types.
"""

import re

from auth.constants import REGEX_EMAIL, REGEX_UUID


class ValidationUtils:
    """Input validation utilities."""
    
    @staticmethod
    def is_valid_email(email: str) -> bool:
        """Validate email format."""
        return bool(re.match(REGEX_EMAIL, email))
    
    @staticmethod
    def is_valid_uuid(uuid_string: str) -> bool:
        """Validate UUID format."""
        return bool(re.match(REGEX_UUID, uuid_string))
    
    @staticmethod
    def sanitize_input(input_string: str, max_length: int = 1000) -> str:
        """Sanitize user input."""
        if not input_string:
            return ""
        
        # Remove null bytes and control characters
        sanitized = ''.join(char for char in input_string if ord(char) >= 32 or char in '\t\n\r')
        
        # Truncate to max length
        return sanitized[:max_length]
