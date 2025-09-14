"""
CSRF token management functionality.
Provides CSRF token generation and verification.
"""

import secrets
import hmac
from datetime import datetime, timedelta, timezone
from typing import Dict, Any

from auth.common.constants import CSRF_TOKEN_LENGTH


class CSRFManager:
    """CSRF token management."""

    def __init__(self):
        self.tokens: Dict[str, Dict[str, Any]] = {}

    def generate_csrf_token(self, session_id: str) -> str:
        """
        Generate CSRF token for a session.

        Args:
            session_id: Session identifier

        Returns:
            CSRF token
        """
        token = secrets.token_urlsafe(CSRF_TOKEN_LENGTH)

        self.tokens[session_id] = {
            "token": token,
            "created_at": datetime.now(timezone.utc),
            "used": False,
        }

        return token

    def verify_csrf_token(
        self, session_id: str, provided_token: str, single_use: bool = True
    ) -> bool:
        """
        Verify CSRF token.

        Args:
            session_id: Session identifier
            provided_token: Token provided by client
            single_use: Whether token should be invalidated after use

        Returns:
            True if token is valid
        """
        if session_id not in self.tokens:
            return False

        token_data = self.tokens[session_id]
        stored_token = token_data["token"]
        created_at = token_data["created_at"]

        # Check if token is expired (1 hour)
        if datetime.now(timezone.utc) - created_at > timedelta(hours=1):
            del self.tokens[session_id]
            return False

        # Check if token was already used (for single-use tokens)
        if single_use and token_data.get("used", False):
            return False

        # Verify token using constant-time comparison
        if not hmac.compare_digest(stored_token, provided_token):
            return False

        # Mark as used if single-use
        if single_use:
            self.tokens[session_id]["used"] = True

        return True

    def invalidate_csrf_token(self, session_id: str):
        """Invalidate CSRF token for a session."""
        if session_id in self.tokens:
            del self.tokens[session_id]
