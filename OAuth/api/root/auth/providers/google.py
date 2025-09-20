"""
Google OAuth provider implementation.
"""

import json
from typing import Dict, Any, Optional
from urllib.parse import urlencode
import requests
from authlib.integrations.requests_client import OAuth2Session
from auth_service.providers.base import BaseOAuthProvider
from auth_service.config import config
from auth_service.exceptions.auth_exceptions import ProviderError

class GoogleOAuthProvider(BaseOAuthProvider):
    """
    Google OAuth provider implementation.
    
    Handles Google OAuth2 authentication flow.
    """
    
    def __init__(self):
        """Initialize Google OAuth provider."""
        self.client_id = config.GOOGLE_CLIENT_ID
        self.client_secret = config.GOOGLE_CLIENT_SECRET
        self.redirect_uri = config.GOOGLE_REDIRECT_URI
        
        # Google OAuth endpoints
        self.auth_url = "https://accounts.google.com/o/oauth2/v2/auth"
        self.token_url = "https://oauth2.googleapis.com/token"
        self.user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo"
        
        # OAuth scopes
        self.scopes = ["openid", "email", "profile"]
        
        if not self.client_id or not self.client_secret:
            raise ProviderError("Google OAuth credentials not configured", "google")
    
    @property
    def provider_name(self) -> str:
        """Get the name of the OAuth provider."""
        return "google"
    
    def get_auth_url(self, state: Optional[str] = None) -> str:
        """
        Get Google OAuth authorization URL.
        
        Args:
            state: Optional state parameter for CSRF protection
            
        Returns:
            Google authorization URL
        """
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": " ".join(self.scopes),
            "response_type": "code",
            "access_type": "offline",
            "prompt": "consent"
        }
        
        if state:
            params["state"] = state
        
        return f"{self.auth_url}?{urlencode(params)}"
    
    def exchange_code(self, auth_code: str, state: Optional[str] = None) -> Dict[str, Any]:
        """
        Exchange authorization code for tokens.
        
        Args:
            auth_code: Authorization code from Google
            state: Optional state parameter for validation
            
        Returns:
            Token response dict containing access_token, id_token, etc.
            
        Raises:
            ProviderError: If token exchange fails
        """
        try:
            # Prepare token request
            token_data = {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "code": auth_code,
                "grant_type": "authorization_code",
                "redirect_uri": self.redirect_uri
            }
            
            # Exchange code for token
            response = requests.post(self.token_url, data=token_data)
            response.raise_for_status()
            
            token_info = response.json()
            
            if not token_info.get("access_token"):
                raise ProviderError("No access token received from Google", "google")
            
            return token_info
            
        except requests.RequestException as e:
            raise ProviderError(f"Failed to exchange code for token: {str(e)}", "google")
        except Exception as e:
            raise ProviderError(f"Google OAuth error: {str(e)}", "google")
    
    async def exchange_code_async(self, auth_code: str, state: Optional[str] = None) -> Dict[str, Any]:
        """Exchange authorization code for tokens (async)."""
        # For now, use synchronous implementation
        # In production, use aiohttp or similar async HTTP client
        return self.exchange_code(auth_code, state)
    
    def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """
        Get user information from Google.
        
        Args:
            access_token: Access token from Google
            
        Returns:
            User information dictionary
            
        Raises:
            ProviderError: If user info retrieval fails
        """
        try:
            headers = {"Authorization": f"Bearer {access_token}"}
            response = requests.get(self.user_info_url, headers=headers)
            response.raise_for_status()
            
            user_data = response.json()
            
            # Map Google user data to our standard format
            return {
                "id": user_data.get("id"),
                "email": user_data.get("email"),
                "first_name": user_data.get("given_name"),
                "last_name": user_data.get("family_name"),
                "name": user_data.get("name"),
                "picture": user_data.get("picture"),
                "verified_email": user_data.get("verified_email", False)
            }
            
        except requests.RequestException as e:
            raise ProviderError(f"Failed to get user info from Google: {str(e)}", "google")
        except Exception as e:
            raise ProviderError(f"Google user info error: {str(e)}", "google")
    
    async def get_user_info_async(self, access_token: str) -> Dict[str, Any]:
        """Get user information from Google (async)."""
        # For now, use synchronous implementation
        # In production, use aiohttp or similar async HTTP client
        return self.get_user_info(access_token)
    
    def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """
        Refresh access token using refresh token.
        
        Args:
            refresh_token: Refresh token from Google
            
        Returns:
            New token information
            
        Raises:
            ProviderError: If token refresh fails
        """
        try:
            token_data = {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token"
            }
            
            response = requests.post(self.token_url, data=token_data)
            response.raise_for_status()
            
            return response.json()
            
        except requests.RequestException as e:
            raise ProviderError(f"Failed to refresh Google token: {str(e)}", "google")
        except Exception as e:
            raise ProviderError(f"Google token refresh error: {str(e)}", "google")
    
    def revoke_token(self, token: str) -> bool:
        """
        Revoke access token.
        
        Args:
            token: Access token to revoke
            
        Returns:
            True if revocation was successful
        """
        try:
            revoke_url = f"https://oauth2.googleapis.com/revoke?token={token}"
            response = requests.post(revoke_url)
            return response.status_code == 200
            
        except Exception:
            return False
