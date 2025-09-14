"""
Password policy enforcement and validation.
"""

import re
from typing import Optional, Dict, Any

from auth.constants import (
    PASSWORD_MIN_LENGTH,
    PASSWORD_REQUIRE_UPPERCASE,
    PASSWORD_REQUIRE_LOWERCASE,
    PASSWORD_REQUIRE_DIGITS,
    PASSWORD_REQUIRE_SPECIAL,
    PASSWORD_SPECIAL_CHARS
)


class PasswordPolicy:
    """Password policy enforcement and validation."""
    
    def __init__(self):
        self.min_length = PASSWORD_MIN_LENGTH
        self.require_uppercase = PASSWORD_REQUIRE_UPPERCASE
        self.require_lowercase = PASSWORD_REQUIRE_LOWERCASE
        self.require_digits = PASSWORD_REQUIRE_DIGITS
        self.require_special = PASSWORD_REQUIRE_SPECIAL
        self.special_chars = PASSWORD_SPECIAL_CHARS
    
    def validate_password(self, password: str, user_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Validate password against policy.
        
        Args:
            password: Password to validate
            user_info: Optional user information for additional checks
        
        Returns:
            Validation result dictionary
        """
        from auth.password.password_manager import password_manager
        
        errors = []
        warnings = []
        
        # Length check
        if len(password) < self.min_length:
            errors.append(f"Password must be at least {self.min_length} characters long")
        
        # Character requirements
        if self.require_uppercase and not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")
        
        if self.require_lowercase and not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")
        
        if self.require_digits and not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one digit")
        
        if self.require_special and not any(c in self.special_chars for c in password):
            errors.append("Password must contain at least one special character")
        
        # Additional security checks
        if user_info:
            email = user_info.get("email", "").lower()
            first_name = user_info.get("first_name", "").lower()
            last_name = user_info.get("last_name", "").lower()
            
            password_lower = password.lower()
            
            # Check if password contains user information
            if email and email.split("@")[0] in password_lower:
                warnings.append("Password should not contain your email address")
            
            if first_name and len(first_name) > 2 and first_name in password_lower:
                warnings.append("Password should not contain your first name")
            
            if last_name and len(last_name) > 2 and last_name in password_lower:
                warnings.append("Password should not contain your last name")
        
        # Common password patterns
        common_patterns = [
            r"123456",
            r"password",
            r"qwerty",
            r"abc123",
            r"admin",
            r"letmein"
        ]
        
        for pattern in common_patterns:
            if re.search(pattern, password.lower()):
                warnings.append("Password contains common patterns that should be avoided")
                break
        
        # Sequential characters
        if self._has_sequential_chars(password):
            warnings.append("Password contains sequential characters")
        
        # Repeated characters
        if self._has_repeated_chars(password):
            warnings.append("Password contains too many repeated characters")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
            "strength_score": password_manager.get_password_strength_score(password)
        }
    
    def _has_sequential_chars(self, password: str, min_length: int = 3) -> bool:
        """Check for sequential characters in password."""
        password_lower = password.lower()
        
        for i in range(len(password_lower) - min_length + 1):
            substring = password_lower[i:i + min_length]
            
            # Check for ascending sequence
            if all(ord(substring[j]) == ord(substring[j-1]) + 1 for j in range(1, len(substring))):
                return True
            
            # Check for descending sequence
            if all(ord(substring[j]) == ord(substring[j-1]) - 1 for j in range(1, len(substring))):
                return True
        
        return False
    
    def _has_repeated_chars(self, password: str, max_repeats: int = 3) -> bool:
        """Check for excessive character repetition."""
        for i in range(len(password) - max_repeats + 1):
            if len(set(password[i:i + max_repeats])) == 1:
                return True
        return False
