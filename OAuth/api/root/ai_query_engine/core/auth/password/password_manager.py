"""
Password management with Argon2 hashing and security features.
Provides secure password hashing, verification, and strength validation.
"""

import re
import secrets
from typing import Optional, Dict, Any
from passlib.context import CryptContext

from auth.configs import config
from auth.constants import (
    PASSWORD_MIN_LENGTH,
    PASSWORD_REQUIRE_UPPERCASE,
    PASSWORD_REQUIRE_LOWERCASE,
    PASSWORD_REQUIRE_DIGITS,
    PASSWORD_REQUIRE_SPECIAL,
    PASSWORD_SPECIAL_CHARS,
    REGEX_PASSWORD_STRENGTH
)
from auth.exceptions import WeakPasswordError
from auth.security.token_utils import token_manager


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
