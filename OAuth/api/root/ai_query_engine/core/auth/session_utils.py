"""
Session and cookie management utilities.
Handles secure cookie operations and session management.
"""

import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, Union
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from .configs import config
from .constants import TOKEN_TYPE_REFRESH
from .exceptions import TokenInvalidError
from .utils import security_utils


class SessionManager:
    """Manages user sessions and secure cookies."""
    
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
            'user_data': user_data,
            'created_at': datetime.now(timezone.utc),
            'last_accessed': datetime.now(timezone.utc),
            'csrf_token': security_utils.generate_secure_token(16)
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
        created_at = session['created_at']
        if datetime.now(timezone.utc) - created_at > timedelta(days=30):
            del self.sessions[session_id]
            return None
        
        # Update last accessed time
        session['last_accessed'] = datetime.now(timezone.utc)
        
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
        
        self.sessions[session_id]['user_data'].update(data)
        self.sessions[session_id]['last_accessed'] = datetime.now(timezone.utc)
        
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
            created_at = session_data['created_at']
            if now - created_at > timedelta(days=30):
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            del self.sessions[session_id]


class CookieManager:
    """Manages secure HTTP cookies."""
    
    def __init__(self):
        self.cookie_name = config.SESSION_COOKIE_NAME
        self.secure = config.SESSION_COOKIE_SECURE
        self.httponly = config.SESSION_COOKIE_HTTPONLY
        self.samesite = config.SESSION_COOKIE_SAMESITE
        self.max_age = config.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60  # seconds
    
    def set_refresh_token_cookie(
        self,
        response: Response,
        refresh_token: str,
        max_age: Optional[int] = None
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
            path="/"
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
            key=self.cookie_name,
            path="/",
            secure=self.secure,
            samesite=self.samesite
        )
    
    def set_session_cookie(
        self,
        response: Response,
        session_id: str,
        max_age: Optional[int] = None
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
            path="/"
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
            key="session_id",
            path="/",
            secure=self.secure,
            samesite=self.samesite
        )
    
    def set_csrf_token_cookie(
        self,
        response: Response,
        csrf_token: str,
        max_age: int = 3600  # 1 hour
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
            path="/"
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
        user_data: Optional[Dict[str, Any]] = None
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
            'refresh_token': self.cookie_manager.get_refresh_token_from_cookie(request),
            'csrf_token': self.cookie_manager.get_csrf_token_from_cookie(request),
            'session_id': self.cookie_manager.get_session_id_from_cookie(request)
        }
    
    def create_auth_response(
        self,
        access_token: str,
        refresh_token: str,
        user_data: Dict[str, Any],
        message: str = "Authentication successful"
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
                "user": user_data
            }
        }
        
        response = JSONResponse(content=response_data)
        self.set_auth_cookies(response, access_token, refresh_token, user_data)
        
        return response
    
    def create_logout_response(
        self,
        request: Request,
        message: str = "Logout successful"
    ) -> JSONResponse:
        """
        Create logout response with cookies cleared.
        
        Args:
            request: FastAPI request object
            message: Response message
        
        Returns:
            JSON response with cookies cleared
        """
        response_data = {
            "success": True,
            "message": message
        }
        
        response = JSONResponse(content=response_data)
        self.clear_auth_cookies(response, request)
        
        return response


# Global instances
session_manager = SessionManager()
cookie_manager = CookieManager()
token_cookie_manager = TokenCookieManager()
