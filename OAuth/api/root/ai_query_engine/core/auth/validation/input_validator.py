"""
Input validation utilities for authentication operations.
Provides comprehensive validation for emails, passwords, and other inputs.
"""

import re
from typing import Dict, Any, List, Optional
from auth.common.constants import (
    REGEX_EMAIL,
    REGEX_PASSWORD_STRENGTH,
    PASSWORD_MIN_LENGTH,
    SUPPORTED_OAUTH_PROVIDERS,
)
from auth.common.exceptions import (
    InvalidEmailError,
    WeakPasswordError,
    AuthBaseException,
)


class InputValidator:
    """Comprehensive input validation for authentication operations."""

    def __init__(self):
        self.email_regex = re.compile(REGEX_EMAIL)
        self.password_regex = re.compile(REGEX_PASSWORD_STRENGTH)

    def validate_email(self, email: str, raise_exception: bool = True) -> bool:
        """
        Validate email format.

        Args:
            email: Email address to validate
            raise_exception: Whether to raise exception on invalid email

        Returns:
            True if email is valid

        Raises:
            InvalidEmailError: If email is invalid and raise_exception is True
        """
        if not email or not isinstance(email, str):
            if raise_exception:
                raise InvalidEmailError("Email is required")
            return False

        email = email.strip().lower()

        # Basic format check
        if not self.email_regex.match(email):
            if raise_exception:
                raise InvalidEmailError("Invalid email format")
            return False

        # Additional checks
        if len(email) > 254:  # RFC 5321 limit
            if raise_exception:
                raise InvalidEmailError("Email address too long")
            return False

        # Check for consecutive dots
        if ".." in email:
            if raise_exception:
                raise InvalidEmailError("Invalid email format")
            return False

        # Check local part length (before @)
        local_part = email.split("@")[0]
        if len(local_part) > 64:  # RFC 5321 limit
            if raise_exception:
                raise InvalidEmailError("Email local part too long")
            return False

        return True

    def validate_password(
        self, password: str, raise_exception: bool = True
    ) -> Dict[str, Any]:
        """
        Validate password strength.

        Args:
            password: Password to validate
            raise_exception: Whether to raise exception on weak password

        Returns:
            Dictionary with validation results

        Raises:
            WeakPasswordError: If password is weak and raise_exception is True
        """
        result = {"valid": True, "errors": [], "warnings": [], "strength_score": 0}

        if not password or not isinstance(password, str):
            result["valid"] = False
            result["errors"].append("Password is required")
            if raise_exception:
                raise WeakPasswordError("Password is required")
            return result

        # Length check
        if len(password) < PASSWORD_MIN_LENGTH:
            result["valid"] = False
            result["errors"].append(
                f"Password must be at least {PASSWORD_MIN_LENGTH} characters long"
            )

        # Character requirements
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = bool(re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]", password))

        if not has_upper:
            result["valid"] = False
            result["errors"].append(
                "Password must contain at least one uppercase letter"
            )

        if not has_lower:
            result["valid"] = False
            result["errors"].append(
                "Password must contain at least one lowercase letter"
            )

        if not has_digit:
            result["valid"] = False
            result["errors"].append("Password must contain at least one digit")

        if not has_special:
            result["valid"] = False
            result["errors"].append(
                "Password must contain at least one special character"
            )

        # Calculate strength score
        score = 0
        if len(password) >= PASSWORD_MIN_LENGTH:
            score += 20
        if len(password) >= 16:
            score += 10
        if len(password) >= 20:
            score += 10
        if has_upper:
            score += 15
        if has_lower:
            score += 15
        if has_digit:
            score += 15
        if has_special:
            score += 15

        result["strength_score"] = score

        # Additional warnings
        if len(password) > 128:
            result["warnings"].append(
                "Password is very long and may cause performance issues"
            )

        # Check for common patterns
        common_patterns = ["123456", "password", "qwerty", "abc123"]
        for pattern in common_patterns:
            if pattern in password.lower():
                result["warnings"].append("Password contains common patterns")
                break

        if not result["valid"] and raise_exception:
            raise WeakPasswordError("; ".join(result["errors"]))

        return result

    def validate_otp_code(self, otp_code: str, raise_exception: bool = True) -> bool:
        """
        Validate OTP code format.

        Args:
            otp_code: OTP code to validate
            raise_exception: Whether to raise exception on invalid code

        Returns:
            True if OTP code format is valid
        """
        if not otp_code or not isinstance(otp_code, str):
            if raise_exception:
                raise AuthBaseException(400, "OTP code is required")
            return False

        otp_code = otp_code.strip()

        # Check length and digits only
        if not (len(otp_code) == 6 and otp_code.isdigit()):
            if raise_exception:
                raise AuthBaseException(400, "OTP code must be 6 digits")
            return False

        return True

    def validate_oauth_provider(
        self, provider: str, raise_exception: bool = True
    ) -> bool:
        """
        Validate OAuth provider.

        Args:
            provider: OAuth provider name
            raise_exception: Whether to raise exception on invalid provider

        Returns:
            True if provider is supported
        """
        if not provider or not isinstance(provider, str):
            if raise_exception:
                raise AuthBaseException(400, "OAuth provider is required")
            return False

        provider = provider.lower().strip()

        if provider not in SUPPORTED_OAUTH_PROVIDERS:
            if raise_exception:
                raise AuthBaseException(
                    400,
                    f"Unsupported OAuth provider. Supported: {SUPPORTED_OAUTH_PROVIDERS}",
                )
            return False

        return True

    def validate_user_registration(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate user registration data.

        Args:
            data: Registration data dictionary

        Returns:
            Validation result dictionary
        """
        result = {"valid": True, "errors": {}, "warnings": {}}

        # Validate email
        email = data.get("email")
        try:
            self.validate_email(email)
        except InvalidEmailError as e:
            result["valid"] = False
            result["errors"]["email"] = str(e.detail)

        # Validate password
        password = data.get("password")
        try:
            password_result = self.validate_password(password)
            if not password_result["valid"]:
                result["valid"] = False
                result["errors"]["password"] = password_result["errors"]
            if password_result["warnings"]:
                result["warnings"]["password"] = password_result["warnings"]
        except WeakPasswordError as e:
            result["valid"] = False
            result["errors"]["password"] = str(e.detail)

        # Validate optional fields
        first_name = data.get("first_name")
        if first_name and (len(first_name) > 50 or len(first_name.strip()) == 0):
            result["errors"]["first_name"] = "First name must be 1-50 characters"
            result["valid"] = False

        last_name = data.get("last_name")
        if last_name and (len(last_name) > 50 or len(last_name.strip()) == 0):
            result["errors"]["last_name"] = "Last name must be 1-50 characters"
            result["valid"] = False

        return result

    def validate_login_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate login data.

        Args:
            data: Login data dictionary

        Returns:
            Validation result dictionary
        """
        result = {"valid": True, "errors": {}, "warnings": {}}

        # Validate email
        email = data.get("email")
        try:
            self.validate_email(email)
        except InvalidEmailError as e:
            result["valid"] = False
            result["errors"]["email"] = str(e.detail)

        # Validate password (basic check, not strength)
        password = data.get("password")
        if not password or not isinstance(password, str) or len(password.strip()) == 0:
            result["valid"] = False
            result["errors"]["password"] = "Password is required"

        # Validate OTP if provided
        otp_code = data.get("otp_code")
        if otp_code:
            try:
                self.validate_otp_code(otp_code)
            except AuthBaseException as e:
                result["valid"] = False
                result["errors"]["otp_code"] = str(e.detail)

        return result

    def sanitize_string(self, value: str, max_length: int = 1000) -> str:
        """
        Sanitize string input.

        Args:
            value: String to sanitize
            max_length: Maximum allowed length

        Returns:
            Sanitized string
        """
        if not value or not isinstance(value, str):
            return ""

        # Remove null bytes and control characters (except common whitespace)
        sanitized = "".join(
            char for char in value if ord(char) >= 32 or char in "\t\n\r"
        )

        # Strip whitespace and truncate
        sanitized = sanitized.strip()[:max_length]

        return sanitized

    def validate_redirect_url(
        self, url: str, allowed_hosts: Optional[List[str]] = None
    ) -> bool:
        """
        Validate redirect URL for security.

        Args:
            url: URL to validate
            allowed_hosts: List of allowed hosts

        Returns:
            True if URL is safe for redirect
        """
        if not url or not isinstance(url, str):
            return False

        url = url.strip()

        # Allow relative URLs
        if url.startswith("/"):
            # Prevent protocol-relative URLs
            if url.startswith("//"):
                return False
            return True

        # For absolute URLs, check against allowed hosts
        if url.startswith(("http://", "https://")):
            try:
                from urllib.parse import urlparse

                parsed = urlparse(url)

                if allowed_hosts:
                    return parsed.netloc in allowed_hosts
                else:
                    # Default to frontend URL host
                    from urllib.parse import urlparse as parse_config
                    from root.ai_query_engine.core.auth.config import config

                    frontend_host = parse_config(config.FRONTEND_URL).netloc
                    return parsed.netloc == frontend_host
            except Exception:
                return False

        # Reject other schemes
        return False


# Global validator instance
input_validator = InputValidator()
