"""
Session management utilities.
Handles user session creation and management.
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
from root.authcommon.config import config
from root.authsecurity import security_utils


class SessionManager:
    """Manages user sessions."""

    def __init__(self):
        self.sessions: Dict[str, Dict[str, Any]] = {}  # Use Redis in production

    def create_session(self, user_data: Dict[str, Any]) -> str:
        """
        Create a new user session.

        Args:
            user_data: User information to store in session

        Returns:
            Session ID
        """
        session_id = security_utils.generate_secure_token(32)

        self.sessions[session_id] = {
            "user_data": user_data,
            "created_at": datetime.now(timezone.utc),
            "last_accessed": datetime.now(timezone.utc),
            "csrf_token": security_utils.generate_secure_token(16),
        }

        return session_id

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Get session data by ID.

        Args:
            session_id: Session identifier

        Returns:
            Session data if exists and valid
        """
        if session_id not in self.sessions:
            return None

        session = self.sessions[session_id]

        # Check if session is expired (30 days)
        created_at = session["created_at"]
        if datetime.now(timezone.utc) - created_at > timedelta(days=30):
            del self.sessions[session_id]
            return None

        # Update last accessed time
        session["last_accessed"] = datetime.now(timezone.utc)

        return session

    def update_session(self, session_id: str, data: Dict[str, Any]) -> bool:
        """
        Update session data.

        Args:
            session_id: Session identifier
            data: Data to update

        Returns:
            True if session was updated
        """
        if session_id not in self.sessions:
            return False

        self.sessions[session_id]["user_data"].update(data)
        self.sessions[session_id]["last_accessed"] = datetime.now(timezone.utc)

        return True

    def delete_session(self, session_id: str) -> bool:
        """
        Delete a session.

        Args:
            session_id: Session identifier

        Returns:
            True if session was deleted
        """
        if session_id in self.sessions:
            del self.sessions[session_id]
            return True
        return False

    def cleanup_expired_sessions(self):
        """Clean up expired sessions."""
        now = datetime.now(timezone.utc)
        expired_sessions = []

        for session_id, session_data in self.sessions.items():
            created_at = session_data["created_at"]
            if now - created_at > timedelta(days=30):
                expired_sessions.append(session_id)

        for session_id in expired_sessions:
            del self.sessions[session_id]


# Global instance
session_manager = SessionManager()
