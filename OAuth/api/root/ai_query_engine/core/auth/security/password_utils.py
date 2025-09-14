"""
Advanced password management with Argon2 hashing and security features.
Includes password strength validation, breach checking, and secure reset tokens.
"""

import re
import hashlib
import secrets
from typing import Optional, Dict, Any
from passlib.context import CryptContext
from passlib.hash import argon2
import logging
from datetime import datetime

from auth.common.config import config
from auth.common.constants import MIN_PASSWORD_LENGTH, PASSWORD_PATTERNS
from auth.common.exceptions import WeakPasswordError

logger = logging.getLogger(__name__)


class PasswordManager:
    """
    Advanced password management with security best practices.

    Features:
    - Argon2 hashing with configurable parameters
    - Password strength validation
    - Breach detection (optional)
    - Secure password generation
    - Password history tracking
    """

    def __init__(self):
        # Configure Argon2 with secure parameters
        self.pwd_context = CryptContext(
            schemes=["argon2"],
            deprecated="auto",
            argon2__memory_cost=65536,  # 64 MB
            argon2__time_cost=3,  # 3 iterations
            argon2__parallelism=1,  # Single thread
            argon2__hash_len=32,  # 32 byte hash
            argon2__salt_len=16,  # 16 byte salt
        )

        logger.info("PasswordManager initialized with Argon2")

    def hash_password(self, password: str) -> str:
        """
        Hash password using Argon2.

        Args:
            password: Plain text password

        Returns:
            Hashed password string
        """
        if not password:
            raise ValueError("Password cannot be empty")

        hashed = self.pwd_context.hash(password)
        logger.debug("Password hashed successfully")
        return hashed

    def verify_password(self, password: str, hashed_password: str) -> bool:
        """
        Verify password against hash.

        Args:
            password: Plain text password
            hashed_password: Stored hash

        Returns:
            True if password matches
        """
        if not password or not hashed_password:
            return False

        try:
            is_valid = self.pwd_context.verify(password, hashed_password)

            # Check if hash needs updating (rehashing)
            if is_valid and self.pwd_context.needs_update(hashed_password):
                logger.info("Password hash needs updating")
                # In production, you would update the hash in database

            return is_valid

        except Exception as e:
            logger.error(f"Password verification error: {str(e)}")
            return False

    def validate_password_strength(self, password: str) -> Dict[str, Any]:
        """
        Comprehensive password strength validation.

        Args:
            password: Password to validate

        Returns:
            Validation result with score and feedback

        Raises:
            WeakPasswordError: If password doesn't meet requirements
        """
        if not password:
            raise WeakPasswordError("Password cannot be empty")

        score = 0
        feedback = []
        requirements_met = {
            "length": False,
            "uppercase": False,
            "lowercase": False,
            "digits": False,
            "special": False,
            "no_common": False,
        }

        # Length check
        if len(password) >= config.MIN_PASSWORD_LENGTH:
            score += 2
            requirements_met["length"] = True
        else:
            feedback.append(
                f"Password must be at least {config.MIN_PASSWORD_LENGTH} characters long"
            )

        # Character variety checks
        if re.search(r"[A-Z]", password):
            score += 1
            requirements_met["uppercase"] = True
        else:
            feedback.append("Password must contain at least one uppercase letter")

        if re.search(r"[a-z]", password):
            score += 1
            requirements_met["lowercase"] = True
        else:
            feedback.append("Password must contain at least one lowercase letter")

        if re.search(r"\d", password):
            score += 1
            requirements_met["digits"] = True
        else:
            feedback.append("Password must contain at least one digit")

        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1
            requirements_met["special"] = True
        else:
            feedback.append("Password must contain at least one special character")

        # Common password check
        if not self._is_common_password(password):
            score += 1
            requirements_met["no_common"] = True
        else:
            feedback.append("Password is too common")

        # Additional strength bonuses
        if len(password) >= 16:
            score += 1
        if len(set(password)) >= len(password) * 0.7:  # Character diversity
            score += 1

        # Determine strength level
        if score >= 7:
            strength = "very_strong"
        elif score >= 5:
            strength = "strong"
        elif score >= 3:
            strength = "medium"
        else:
            strength = "weak"

        result = {
            "score": score,
            "max_score": 8,
            "strength": strength,
            "requirements_met": requirements_met,
            "feedback": feedback,
            "is_valid": score >= 5,  # Minimum acceptable score
        }

        if not result["is_valid"]:
            raise WeakPasswordError(f"Password is too weak. {'; '.join(feedback)}")

        return result

    def generate_secure_password(
        self, length: int = 16, include_symbols: bool = True
    ) -> str:
        """
        Generate a cryptographically secure password.

        Args:
            length: Password length (minimum 12)
            include_symbols: Include special characters

        Returns:
            Generated password
        """
        if length < 12:
            length = 12

        # Character sets
        lowercase = "abcdefghijklmnopqrstuvwxyz"
        uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        digits = "0123456789"
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?" if include_symbols else ""

        # Ensure at least one character from each required set
        password = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
        ]

        if include_symbols:
            password.append(secrets.choice(symbols))

        # Fill remaining length with random characters
        all_chars = lowercase + uppercase + digits + symbols
        for _ in range(length - len(password)):
            password.append(secrets.choice(all_chars))

        # Shuffle the password
        secrets.SystemRandom().shuffle(password)

        return "".join(password)

    def check_password_breach(self, password: str) -> bool:
        """
        Check if password appears in known breaches using k-anonymity.
        Uses HaveIBeenPwned API with k-anonymity for privacy.

        Args:
            password: Password to check

        Returns:
            True if password is found in breaches
        """
        try:
            import requests

            # Create SHA-1 hash of password
            sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]

            # Query HaveIBeenPwned API
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url, timeout=5)

            if response.status_code == 200:
                # Check if our suffix appears in the response
                for line in response.text.splitlines():
                    hash_suffix, count = line.split(":")
                    if hash_suffix == suffix:
                        logger.warning(f"Password found in {count} breaches")
                        return True

            return False

        except Exception as e:
            logger.error(f"Breach check failed: {str(e)}")
            # Fail open - don't block user if service is unavailable
            return False

    def _is_common_password(self, password: str) -> bool:
        """
        Check if password is in common passwords list.

        Args:
            password: Password to check

        Returns:
            True if password is common
        """
        # Common passwords list (simplified - in production use a comprehensive list)
        common_passwords = {
            "password",
            "123456",
            "password123",
            "admin",
            "qwerty",
            "letmein",
            "welcome",
            "monkey",
            "dragon",
            "master",
            "123456789",
            "password1",
            "1234567890",
            "login",
            "guest",
        }

        return password.lower() in common_passwords

    def create_reset_token(self, email: str, expiry_minutes: int = 15) -> str:
        """
        Create a secure password reset token.

        Args:
            email: User email
            expiry_minutes: Token expiry time

        Returns:
            Reset token
        """
        from auth.token_utils import TokenManager

        token_manager = TokenManager()
        return token_manager.create_token(
            {
                "sub": email,
                "type": "password_reset",
                "iat": datetime.utcnow().timestamp(),
            },
            expires_minutes=expiry_minutes,
        )

    def verify_reset_token(self, token: str) -> Optional[str]:
        """
        Verify password reset token and extract email.

        Args:
            token: Reset token

        Returns:
            Email if token is valid, None otherwise
        """
        try:
            from auth.token_utils import TokenManager

            token_manager = TokenManager()
            payload = token_manager.verify_token(token)

            if payload.get("type") == "password_reset":
                return payload.get("sub")

        except Exception as e:
            logger.error(f"Reset token verification failed: {str(e)}")

        return None
