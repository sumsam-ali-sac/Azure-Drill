"""
Cookie management utilities.
Handles secure HTTP cookie operations.
"""

from typing import Optional
from fastapi import Request, Response
from auth.common import config


class CookieManager:
    """Manages secure HTTP cookies."""

    def __init__(self):
        self.cookie_name = config.SESSION_COOKIE_NAME
        self.secure = config.SESSION_COOKIE_SECURE
        self.httponly = config.SESSION_COOKIE_HTTPONLY
        self.samesite = config.SESSION_COOKIE_SAMESITE
        self.max_age = config.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60  # seconds

    def set_refresh_token_cookie(
        self, response: Response, refresh_token: str, max_age: Optional[int] = None
    ):
        """
        Set refresh token in secure HTTP-only cookie.

        Args:
            response: FastAPI response object
            refresh_token: JWT refresh token
            max_age: Cookie max age in seconds
        """
        max_age = max_age or self.max_age

        response.set_cookie(
            key=self.cookie_name,
            value=refresh_token,
            max_age=max_age,
            httponly=self.httponly,
            secure=self.secure,
            samesite=self.samesite,
            path="/",
        )

    def get_refresh_token_from_cookie(self, request: Request) -> Optional[str]:
        """
        Get refresh token from cookie.

        Args:
            request: FastAPI request object

        Returns:
            Refresh token if present in cookie
        """
        return request.cookies.get(self.cookie_name)

    def clear_refresh_token_cookie(self, response: Response):
        """
        Clear refresh token cookie.

        Args:
            response: FastAPI response object
        """
        response.delete_cookie(
            key=self.cookie_name, path="/", secure=self.secure, samesite=self.samesite
        )

    def set_session_cookie(
        self, response: Response, session_id: str, max_age: Optional[int] = None
    ):
        """
        Set session ID in cookie.

        Args:
            response: FastAPI response object
            session_id: Session identifier
            max_age: Cookie max age in seconds
        """
        max_age = max_age or self.max_age

        response.set_cookie(
            key="session_id",
            value=session_id,
            max_age=max_age,
            httponly=True,
            secure=self.secure,
            samesite=self.samesite,
            path="/",
        )

    def get_session_id_from_cookie(self, request: Request) -> Optional[str]:
        """
        Get session ID from cookie.

        Args:
            request: FastAPI request object

        Returns:
            Session ID if present in cookie
        """
        return request.cookies.get("session_id")

    def clear_session_cookie(self, response: Response):
        """
        Clear session cookie.

        Args:
            response: FastAPI response object
        """
        response.delete_cookie(
            key="session_id", path="/", secure=self.secure, samesite=self.samesite
        )

    def set_csrf_token_cookie(
        self, response: Response, csrf_token: str, max_age: int = 3600  # 1 hour
    ):
        """
        Set CSRF token in cookie.

        Args:
            response: FastAPI response object
            csrf_token: CSRF token
            max_age: Cookie max age in seconds
        """
        response.set_cookie(
            key="csrf_token",
            value=csrf_token,
            max_age=max_age,
            httponly=False,  # CSRF token needs to be accessible to JavaScript
            secure=self.secure,
            samesite=self.samesite,
            path="/",
        )

    def get_csrf_token_from_cookie(self, request: Request) -> Optional[str]:
        """
        Get CSRF token from cookie.

        Args:
            request: FastAPI request object

        Returns:
            CSRF token if present in cookie
        """
        return request.cookies.get("csrf_token")


cookie_manager = CookieManager()
