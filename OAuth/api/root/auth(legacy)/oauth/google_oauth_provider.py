"""
Google OAuth provider implementation.
"""

import requests
from typing import Dict, Any, Optional
from urllib.parse import urlencode

from root.authoroot.authoauth_provider import OAuthProvider
from root.authcommon.constants import (
    OAUTH_PROVIDER_GOOGLE,
    GOOGLE_OAUTH_SCOPES,
    GOOGLE_OAUTH_URLS,
)
from root.authcommon.exceptions import OAuthError
from root.authcommon.config import config
from root.authsecurity.token_utils import token_manager


class GoogleOAuthProvider(OAuthProvider):
    """Google OAuth provider implementation."""

    def __init__(self, client_id: str, client_secret: str):
        super().__init__(OAUTH_PROVIDER_GOOGLE, client_id, client_secret)
        self.urls = GOOGLE_OAUTH_URLS
        self.scopes = GOOGLE_OAUTH_SCOPES

    def get_authorization_url(
        self, redirect_uri: str, state: str, scopes: Optional[list] = None, **kwargs
    ) -> str:
        """
        Get Google OAuth authorization URL.

        Args:
            redirect_uri: Callback URL
            state: CSRF state parameter
            scopes: OAuth scopes (defaults to configured scopes)

        Returns:
            Authorization URL
        """
        scopes = scopes or self.scopes

        params = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(scopes),
            "response_type": "code",
            "state": state,
            "access_type": "offline",  # For refresh tokens
            "prompt": "consent",  # Force consent screen
        }

        return f"{self.urls['authorize']}?{urlencode(params)}"

    def exchange_code_for_token(
        self, code: str, redirect_uri: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Exchange authorization code for access token.

        Args:
            code: Authorization code
            redirect_uri: Callback URL

        Returns:
            Token response dictionary
        """
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
        }

        try:
            response = requests.post(
                self.urls["token"],
                data=data,
                headers={"Accept": "application/json"},
                timeout=10,
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            raise OAuthError(f"Failed to exchange code for token: {str(e)}", self.name)

    def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """
        Get user information from Google.

        Args:
            access_token: OAuth access token

        Returns:
            User information dictionary
        """
        headers = {"Authorization": f"Bearer {access_token}"}

        try:
            response = requests.get(self.urls["userinfo"], headers=headers, timeout=10)
            response.raise_for_status()
            user_data = response.json()

            # Normalize user data
            return {
                "id": user_data.get("id"),
                "email": user_data.get("email"),
                "first_name": user_data.get("given_name"),
                "last_name": user_data.get("family_name"),
                "name": user_data.get("name"),
                "picture": user_data.get("picture"),
                "verified_email": user_data.get("verified_email", False),
                "provider": self.name,
                "raw_data": user_data,
            }
        except requests.RequestException as e:
            raise OAuthError(f"Failed to get user info: {str(e)}", self.name)

    def verify_id_token(self, id_token: str) -> Dict[str, Any]:
        """
        Verify Google ID token.

        Args:
            id_token: JWT ID token from Google

        Returns:
            Verified token payload
        """
        try:
            return token_manager.verify_token(
                id_token,
                jwks_url=config.GOOGLE_JWKS_URL,
                audience=self.client_id,
                issuer="https://accounts.google.com",
            )
        except Exception as e:
            raise OAuthError(f"Failed to verify ID token: {str(e)}", self.name)
