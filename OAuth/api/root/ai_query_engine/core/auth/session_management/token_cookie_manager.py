"""
Token-based authentication management with cookies.
Combines session and cookie management for authentication.
"""

from typing import Dict, Any, Optional
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from auth.session_management import SessionManager, CookieManager
from auth.common.config import config
from auth.security import security_utils


class TokenCookieManager:
    """Specialized manager for token-based authentication with cookies."""

    def __init__(self):
        self.cookie_manager = CookieManager()
        self.session_manager = SessionManager()

    def set_auth_cookies(
        self,
        response: Response,
        access_token: str,
        refresh_token: str,
        user_data: Optional[Dict[str, Any]] = None,
    ):
        """
        Set authentication cookies.

        Args:
            response: FastAPI response object
            access_token: JWT access token
            refresh_token: JWT refresh token
            user_data: Optional user data for session
        """
        # Set refresh token in HTTP-only cookie
        self.cookie_manager.set_refresh_token_cookie(response, refresh_token)

        # Optionally create session for additional data
        if user_data:
            session_id = self.session_manager.create_session(user_data)
            self.cookie_manager.set_session_cookie(response, session_id)

        # Generate and set CSRF token
        csrf_token = security_utils.generate_secure_token(16)
        self.cookie_manager.set_csrf_token_cookie(response, csrf_token)

    def clear_auth_cookies(self, response: Response, request: Request):
        """
        Clear all authentication cookies.

        Args:
            response: FastAPI response object
            request: FastAPI request object
        """
        # Clear refresh token cookie
        self.cookie_manager.clear_refresh_token_cookie(response)

        # Clear session cookie and data
        session_id = self.cookie_manager.get_session_id_from_cookie(request)
        if session_id:
            self.session_manager.delete_session(session_id)
            self.cookie_manager.clear_session_cookie(response)

        # Clear CSRF token cookie
        response.delete_cookie("csrf_token", path="/")

    def get_tokens_from_cookies(self, request: Request) -> Dict[str, Optional[str]]:
        """
        Get tokens from cookies.

        Args:
            request: FastAPI request object

        Returns:
            Dictionary with token information
        """
        return {
            "refresh_token": self.cookie_manager.get_refresh_token_from_cookie(request),
            "csrf_token": self.cookie_manager.get_csrf_token_from_cookie(request),
            "session_id": self.cookie_manager.get_session_id_from_cookie(request),
        }

    def create_auth_response(
        self,
        access_token: str,
        refresh_token: str,
        user_data: Dict[str, Any],
        message: str = "Authentication successful",
    ) -> JSONResponse:
        """
        Create authentication response with cookies.

        Args:
            access_token: JWT access token
            refresh_token: JWT refresh token
            user_data: User information
            message: Response message

        Returns:
            JSON response with cookies set
        """
        response_data = {
            "success": True,
            "message": message,
            "data": {
                "access_token": access_token,
                "token_type": "bearer",
                "expires_in": config.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                "user": user_data,
            },
        }

        response = JSONResponse(content=response_data)
        self.set_auth_cookies(response, access_token, refresh_token, user_data)

        return response

    def create_logout_response(
        self, request: Request, message: str = "Logout successful"
    ) -> JSONResponse:
        """
        Create logout response with cookies cleared.

        Args:
            request: FastAPI request object
            message: Response message

        Returns:
            JSON response with cookies cleared
        """
        response_data = {"success": True, "message": message}

        response = JSONResponse(content=response_data)
        self.clear_auth_cookies(response, request)

        return response


# Global instance
token_cookie_manager = TokenCookieManager()
