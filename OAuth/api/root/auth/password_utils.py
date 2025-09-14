"""
Password management utilities with Argon2 hashing and security features.
Provides secure password hashing, verification, and strength validation.
"""

import re
import secrets
from typing import Optional, Dict, Any
from passlib.context import CryptContext
from passlib.hash import argon2
from .configs import config
from .constants import (
    PASSWORD_MIN_LENGTH,
    PASSWORD_REQUIRE_UPPERCASE,
    PASSWORD_REQUIRE_LOWERCASE,
    PASSWORD_REQUIRE_DIGITS,
    PASSWORD_REQUIRE_SPECIAL,
    PASSWORD_SPECIAL_CHARS,
    REGEX_PASSWORD_STRENGTH
)
from .exceptions import WeakPasswordError, AuthConfigurationError
from .token_utils import token_manager


class PasswordManager:
    """Manages password operations with advanced security features."""
    
    def __init__(self):
        # Configure Argon2 context with secure parameters
        self.pwd_context = CryptContext(
            schemes=["argon2"],
            deprecated="auto",
            argon2__memory_cost=65536,  # 64 MB
            argon2__time_cost=3,        # 3 iterations
            argon2__parallelism=1,      # Single thread
            argon2__hash_len=32,        # 32 byte hash
            argon2__salt_len=16,        # 16 byte salt
        )
    
    def hash_password(self, password: str) -> str:
        """
        Hash a password using Argon2.
        
        Args:
            password: Plain text password
        
        Returns:
            Hashed password string
        """
        if not self.is_password_strong(password):
            raise WeakPasswordError("Password does not meet security requirements")
        
        return self.pwd_context.hash(password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash.
        
        Args:
            plain_password: Plain text password
            hashed_password: Hashed password to verify against
        
        Returns:
            True if password matches hash
        """
        try:
            return self.pwd_context.verify(plain_password, hashed_password)
        except Exception:
            return False
    
    def is_password_strong(self, password: str) -> bool:
        """
        Check if password meets strength requirements.
        
        Args:
            password: Password to check
        
        Returns:
            True if password is strong enough
        """
        if len(password) < PASSWORD_MIN_LENGTH:
            return False
        
        # Check regex pattern
        if not re.match(REGEX_PASSWORD_STRENGTH, password):
            return False
        
        # Additional checks
        checks = []
        
        if PASSWORD_REQUIRE_UPPERCASE:
            checks.append(any(c.isupper() for c in password))
        
        if PASSWORD_REQUIRE_LOWERCASE:
            checks.append(any(c.islower() for c in password))
        
        if PASSWORD_REQUIRE_DIGITS:
            checks.append(any(c.isdigit() for c in password))
        
        if PASSWORD_REQUIRE_SPECIAL:
            checks.append(any(c in PASSWORD_SPECIAL_CHARS for c in password))
        
        return all(checks)
    
    def get_password_strength_score(self, password: str) -> Dict[str, Any]:
        """
        Get detailed password strength analysis.
        
        Args:
            password: Password to analyze
        
        Returns:
            Dictionary with strength analysis
        """
        score = 0
        feedback = []
        
        # Length check
        if len(password) >= PASSWORD_MIN_LENGTH:
            score += 20
        else:
            feedback.append(f"Password must be at least {PASSWORD_MIN_LENGTH} characters long")
        
        # Character type checks
        if any(c.islower() for c in password):
            score += 15
        else:
            feedback.append("Add lowercase letters")
        
        if any(c.isupper() for c in password):
            score += 15
        else:
            feedback.append("Add uppercase letters")
        
        if any(c.isdigit() for c in password):
            score += 15
        else:
            feedback.append("Add numbers")
        
        if any(c in PASSWORD_SPECIAL_CHARS for c in password):
            score += 15
        else:
            feedback.append("Add special characters")
        
        # Length bonus
        if len(password) >= 16:
            score += 10
        if len(password) >= 20:
            score += 10
        
        # Determine strength level
        if score >= 90:
            strength = "very_strong"
        elif score >= 70:
            strength = "strong"
        elif score >= 50:
            strength = "medium"
        elif score >= 30:
            strength = "weak"
        else:
            strength = "very_weak"
        
        return {
            "score": score,
            "strength": strength,
            "feedback": feedback,
            "is_strong": score >= 70
        }
    
    def generate_secure_password(self, length: int = 16) -> str:
        """
        Generate a cryptographically secure password.
        
        Args:
            length: Password length (minimum 12)
        
        Returns:
            Generated secure password
        """
        if length < PASSWORD_MIN_LENGTH:
            length = PASSWORD_MIN_LENGTH
        
        # Character sets
        lowercase = "abcdefghijklmnopqrstuvwxyz"
        uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        digits = "0123456789"
        special = PASSWORD_SPECIAL_CHARS
        
        # Ensure at least one character from each required set
        password = []
        if PASSWORD_REQUIRE_LOWERCASE:
            password.append(secrets.choice(lowercase))
        if PASSWORD_REQUIRE_UPPERCASE:
            password.append(secrets.choice(uppercase))
        if PASSWORD_REQUIRE_DIGITS:
            password.append(secrets.choice(digits))
        if PASSWORD_REQUIRE_SPECIAL:
            password.append(secrets.choice(special))
        
        # Fill remaining length with random characters
        all_chars = lowercase + uppercase + digits + special
        for _ in range(length - len(password)):
            password.append(secrets.choice(all_chars))
        
        # Shuffle the password
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)
    
    def create_password_reset_token(self, email: str) -> str:
        """
        Create a password reset token.
        
        Args:
            email: User email address
        
        Returns:
            Password reset token
        """
        return token_manager.create_password_reset_token(email)
    
    def verify_password_reset_token(self, token: str) -> str:
        """
        Verify password reset token and return email.
        
        Args:
            token: Password reset token
        
        Returns:
            User email from token
        """
        return token_manager.verify_password_reset_token(token)
    
    def needs_rehash(self, hashed_password: str) -> bool:
        """
        Check if password hash needs to be updated.
        
        Args:
            hashed_password: Current password hash
        
        Returns:
            True if hash should be updated
        """
        return self.pwd_context.needs_update(hashed_password)
    
    def get_hash_info(self, hashed_password: str) -> Dict[str, Any]:
        """
        Get information about a password hash.
        
        Args:
            hashed_password: Password hash to analyze
        
        Returns:
            Hash information dictionary
        """
        try:
            return self.pwd_context.identify(hashed_password)
        except Exception:
            return {"scheme": "unknown", "valid": False}


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


# Global password manager instance
password_manager = PasswordManager()
password_policy = PasswordPolicy()
