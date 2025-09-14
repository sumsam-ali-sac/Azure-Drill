"""
General security utilities.
Provides token generation, hashing, and validation functions.
"""

import secrets
import hashlib
import hmac
from typing import Optional, List
from urllib.parse import urlparse

from auth.common.config import config


class SecurityUtils:
    """General security utilities."""

    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """Generate cryptographically secure token."""
        return secrets.token_urlsafe(length)

    @staticmethod
    def generate_state_token() -> str:
        """Generate OAuth state token."""
        return secrets.token_urlsafe(32)

    @staticmethod
    def hash_token(token: str, salt: Optional[str] = None) -> str:
        """Hash a token with optional salt."""
        if salt is None:
            salt = secrets.token_hex(16)

        combined = f"{token}{salt}"
        hashed = hashlib.sha256(combined.encode()).hexdigest()
        return f"{salt}:{hashed}"

    @staticmethod
    def verify_hashed_token(token: str, hashed_token: str) -> bool:
        """Verify token against its hash."""
        try:
            salt, expected_hash = hashed_token.split(":", 1)
            combined = f"{token}{salt}"
            actual_hash = hashlib.sha256(combined.encode()).hexdigest()
            return hmac.compare_digest(expected_hash, actual_hash)
        except ValueError:
            return False

    @staticmethod
    def sanitize_email(email: str) -> str:
        """Sanitize email address."""
        return email.lower().strip()

    @staticmethod
    def is_safe_redirect_url(
        url: str, allowed_hosts: Optional[List[str]] = None
    ) -> bool:
        """Check if redirect URL is safe."""
        if not url:
            return False

        # Check for absolute URLs
        if url.startswith(("http://", "https://")):
            parsed = urlparse(url)

            if allowed_hosts:
                return parsed.netloc in allowed_hosts
            else:
                # Only allow same host as configured frontend URL
                frontend_host = urlparse(config.FRONTEND_URL).netloc
                return parsed.netloc == frontend_host

        # Relative URLs are generally safe
        return url.startswith("/")
