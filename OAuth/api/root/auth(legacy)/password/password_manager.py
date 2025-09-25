"""
Password management with Argon2 hashing and security features.
Provides secure password hashing, verification, and strength validation.
"""

import re
import secrets
from typing import Optional, Dict, Any
from passlib.context import CryptContext

from root.authcommon.config import config
from root.authcommon.constants import (
    PASSWORD_MIN_LENGTH,
    PASSWORD_REQUIRE_UPPERCASE,
    PASSWORD_REQUIRE_LOWERCASE,
    PASSWORD_REQUIRE_DIGITS,
    PASSWORD_REQUIRE_SPECIAL,
    PASSWORD_SPECIAL_CHARS,
    REGEX_PASSWORD_STRENGTH,
)
from root.authcommon.exceptions import WeakPasswordError
from root.authsecurity.token_utils import token_manager


class PasswordManager:
    """Manages password operations with advanced security and policy enforcement."""

    def __init__(self):
        # Configure Argon2 context with secure parameters
        self.pwd_context = CryptContext(
            schemes=["argon2"],
            deprecated="auto",
            argon2__memory_cost=65536,  # 64 MB
            argon2__time_cost=3,  # 3 iterations
            argon2__parallelism=1,  # Single thread
            argon2__hash_len=32,  # 32 byte hash
            argon2__salt_len=16,  # 16 byte salt
        )
        self.min_length = PASSWORD_MIN_LENGTH
        self.require_uppercase = PASSWORD_REQUIRE_UPPERCASE
        self.require_lowercase = PASSWORD_REQUIRE_LOWERCASE
        self.require_digits = PASSWORD_REQUIRE_DIGITS
        self.require_special = PASSWORD_REQUIRE_SPECIAL
        self.special_chars = PASSWORD_SPECIAL_CHARS

    def hash_password(self, password: str) -> str:
        """
        Hash a password using Argon2 after validation.

        Args:
            password: Plain text password

        Returns:
            Hashed password string

        Raises:
            WeakPasswordError: If password does not meet security requirements
        """
        validation_result = self.validate_password(password)
        if not validation_result["valid"]:
            raise WeakPasswordError(
                "Password does not meet security requirements: "
                + "; ".join(validation_result["errors"])
            )
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

    def validate_password(
        self, password: str, user_info: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Validate password against policy and provide strength analysis.

        Args:
            password: Password to validate
            user_info: Optional user information for additional checks

        Returns:
            Validation result dictionary with errors, warnings, and strength score
        """
        errors = []
        warnings = []
        score = 0

        # Length check
        if len(password) < self.min_length:
            errors.append(
                f"Password must be at least {self.min_length} characters long"
            )
        else:
            score += 20

        # Character requirements
        if self.require_uppercase and not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")
        else:
            score += 15

        if self.require_lowercase and not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")
        else:
            score += 15

        if self.require_digits and not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one digit")
        else:
            score += 15

        if self.require_special and not any(c in self.special_chars for c in password):
            errors.append("Password must contain at least one special character")
        else:
            score += 15

        # Regex pattern check
        if not re.match(REGEX_PASSWORD_STRENGTH, password):
            errors.append("Password does not match required pattern")

        # Additional security checks
        if user_info:
            email = user_info.get("email", "").lower()
            first_name = user_info.get("first_name", "").lower()
            last_name = user_info.get("last_name", "").lower()
            password_lower = password.lower()

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
            r"letmein",
        ]
        for pattern in common_patterns:
            if re.search(pattern, password.lower()):
                warnings.append(
                    "Password contains common patterns that should be avoided"
                )
                break

        # Sequential and repeated characters
        if self._has_sequential_chars(password):
            warnings.append("Password contains sequential characters")
        if self._has_repeated_chars(password):
            warnings.append("Password contains too many repeated characters")

        # Length bonus
        if len(password) >= 16:
            score += 10
        if len(password) >= 20:
            score += 10

        # Determine strength level
        strength = (
            "very_strong"
            if score >= 90
            else (
                "strong"
                if score >= 70
                else "medium" if score >= 50 else "weak" if score >= 30 else "very_weak"
            )
        )

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
            "score": score,
            "strength": strength,
            "is_strong": score >= 70,
        }

    def _has_sequential_chars(self, password: str, min_length: int = 3) -> bool:
        """Check for sequential characters in password."""
        password_lower = password.lower()
        for i in range(len(password_lower) - min_length + 1):
            substring = password_lower[i : i + min_length]
            if all(
                ord(substring[j]) == ord(substring[j - 1]) + 1
                for j in range(1, len(substring))
            ):
                return True
            if all(
                ord(substring[j]) == ord(substring[j - 1]) - 1
                for j in range(1, len(substring))
            ):
                return True
        return False

    def _has_repeated_chars(self, password: str, max_repeats: int = 3) -> bool:
        """Check for excessive character repetition."""
        for i in range(len(password) - max_repeats + 1):
            if len(set(password[i : i + max_repeats])) == 1:
                return True
        return False

    def generate_secure_password(self, length: int = 16) -> str:
        """
        Generate a cryptographically secure password.

        Args:
            length: Password length (minimum 12)

        Returns:
            Generated secure password
        """
        if length < self.min_length:
            length = self.min_length

        lowercase = "abcdefghijklmnopqrstuvwxyz"
        uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        digits = "0123456789"
        special = self.special_chars

        password = []
        if self.require_lowercase:
            password.append(secrets.choice(lowercase))
        if self.require_uppercase:
            password.append(secrets.choice(uppercase))
        if self.require_digits:
            password.append(secrets.choice(digits))
        if self.require_special:
            password.append(secrets.choice(special))

        all_chars = lowercase + uppercase + digits + special
        for _ in range(length - len(password)):
            password.append(secrets.choice(all_chars))

        secrets.SystemRandom().shuffle(password)
        return "".join(password)

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
