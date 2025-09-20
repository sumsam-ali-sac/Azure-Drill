"""
Input validators for authentication data.
"""

import re
from typing import Dict, List, Any
from auth_service.config import config

class EmailValidator:
    """Email address validator."""
    
    def __init__(self):
        """Initialize email validator with regex pattern."""
        # RFC 5322 compliant email regex (simplified)
        self.email_pattern = re.compile(
            r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        )
    
    def validate(self, email: str) -> bool:
        """
        Validate email address format.
        
        Args:
            email: Email address to validate
            
        Returns:
            True if email is valid, False otherwise
        """
        if not email or not isinstance(email, str):
            return False
        
        # Check length
        if len(email) > 254:  # RFC 5321 limit
            return False
        
        # Check format
        return bool(self.email_pattern.match(email.lower()))
    
    def normalize(self, email: str) -> str:
        """
        Normalize email address (lowercase).
        
        Args:
            email: Email address to normalize
            
        Returns:
            Normalized email address
        """
        return email.lower().strip() if email else ""

class PasswordValidator:
    """Password strength validator."""
    
    def __init__(self):
        """Initialize password validator with policy settings."""
        self.min_length = config.MIN_PASSWORD_LENGTH
        self.require_uppercase = config.REQUIRE_UPPERCASE
        self.require_lowercase = config.REQUIRE_LOWERCASE
        self.require_numbers = config.REQUIRE_NUMBERS
        self.require_special_chars = config.REQUIRE_SPECIAL_CHARS
        
        # Special characters pattern
        self.special_chars_pattern = re.compile(r'[!@#$%^&*(),.?":{}|<>]')
    
    def validate(self, password: str) -> Dict[str, Any]:
        """
        Validate password strength.
        
        Args:
            password: Password to validate
            
        Returns:
            Dictionary with validation results:
            {
                "is_valid": bool,
                "errors": List[str],
                "strength_score": int (0-100)
            }
        """
        if not password or not isinstance(password, str):
            return {
                "is_valid": False,
                "errors": ["Password is required"],
                "strength_score": 0
            }
        
        errors = []
        score = 0
        
        # Check minimum length
        if len(password) < self.min_length:
            errors.append(f"Password must be at least {self.min_length} characters long")
        else:
            score += 20
        
        # Check uppercase requirement
        if self.require_uppercase and not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        elif re.search(r'[A-Z]', password):
            score += 20
        
        # Check lowercase requirement
        if self.require_lowercase and not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        elif re.search(r'[a-z]', password):
            score += 20
        
        # Check numbers requirement
        if self.require_numbers and not re.search(r'\d', password):
            errors.append("Password must contain at least one number")
        elif re.search(r'\d', password):
            score += 20
        
        # Check special characters requirement
        if self.require_special_chars and not self.special_chars_pattern.search(password):
            errors.append("Password must contain at least one special character")
        elif self.special_chars_pattern.search(password):
            score += 20
        
        # Additional strength checks
        if len(password) >= 12:
            score += 10  # Bonus for longer passwords
        
        if len(set(password)) >= len(password) * 0.7:
            score += 10  # Bonus for character diversity
        
        # Check for common weak patterns
        weak_patterns = [
            r'123456',
            r'password',
            r'qwerty',
            r'abc123',
            r'admin',
            r'letmein'
        ]
        
        for pattern in weak_patterns:
            if re.search(pattern, password.lower()):
                errors.append("Password contains common weak patterns")
                score -= 20
                break
        
        # Ensure score is within bounds
        score = max(0, min(100, score))
        
        return {
            "is_valid": len(errors) == 0,
            "errors": errors,
            "strength_score": score
        }
    
    def get_strength_label(self, score: int) -> str:
        """
        Get password strength label based on score.
        
        Args:
            score: Password strength score (0-100)
            
        Returns:
            Strength label
        """
        if score >= 80:
            return "Very Strong"
        elif score >= 60:
            return "Strong"
        elif score >= 40:
            return "Medium"
        elif score >= 20:
            return "Weak"
        else:
            return "Very Weak"

class OAuthTokenValidator:
    """OAuth token validator (future functionality)."""
    
    def validate_authorization_code(self, code: str) -> bool:
        """
        Validate OAuth authorization code format.
        
        Args:
            code: Authorization code to validate
            
        Returns:
            True if code format is valid, False otherwise
        """
        if not code or not isinstance(code, str):
            return False
        
        # Basic format validation (varies by provider)
        return len(code) >= 10 and code.isalnum()
    
    def validate_state_parameter(self, state: str) -> bool:
        """
        Validate OAuth state parameter.
        
        Args:
            state: State parameter to validate
            
        Returns:
            True if state is valid, False otherwise
        """
        if not state or not isinstance(state, str):
            return False
        
        # State should be a secure random string
        return len(state) >= 16 and re.match(r'^[a-zA-Z0-9_-]+$', state)

class OTPValidator:
    """OTP code validator (future functionality)."""
    
    def validate_totp_code(self, code: str) -> bool:
        """
        Validate TOTP code format.
        
        Args:
            code: TOTP code to validate
            
        Returns:
            True if code format is valid, False otherwise
        """
        if not code or not isinstance(code, str):
            return False
        
        # TOTP codes are typically 6 digits
        return len(code) == 6 and code.isdigit()
    
    def validate_backup_code(self, code: str) -> bool:
        """
        Validate backup recovery code format.
        
        Args:
            code: Backup code to validate
            
        Returns:
            True if code format is valid, False otherwise
        """
        if not code or not isinstance(code, str):
            return False
        
        # Backup codes are typically 8-10 characters, alphanumeric
        return 8 <= len(code) <= 10 and re.match(r'^[a-zA-Z0-9]+$', code)
