"""
Google OAuth provider implementation.
"""

from typing import Dict, Any, Optional
from urllib.parse import urlencode
import httpx
from auth.providers.base import BaseOAuthProvider
from auth.config import config
from auth.exceptions.auth_exceptions import ProviderError, ValidationError
import logging

# Configure logging
logger = logging.getLogger(__name__)


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
        self.auth_url = "https://accounts.google.com/o/oauth2/v2/auth"
        self.token_url = "https://oauth2.googleapis.com/token"
        self.user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo"
        self.scopes = ["openid", "email", "profile"]

        if not all([self.client_id, self.client_secret, self.redirect_uri]):
            raise ProviderError("Google OAuth credentials not configured", "google")

    @property
    def provider_name(self) -> str:
        """Get the name of the OAuth provider."""
        return "google"

    def get_auth_url(self, state: Optional[str] = None) -> str:
        """
        Get Google OAuth authorization URL.
        """
        try:
            params = self._build_auth_params(
                {
                    "client_id": self.client_id,
                    "redirect_uri": self.redirect_uri,
                    "scope": " ".join(self.scopes),
                    "response_type": "code",
                    "access_type": "offline",
                    "prompt": "consent",
                },
                state=state,
            )
            return f"{self.auth_url}?{urlencode(params)}"
        except Exception as e:
            logger.error(f"Failed to generate Google auth URL: {str(e)}", exc_info=True)
            raise ProviderError(
                f"Failed to generate Google auth URL: {str(e)}", "google"
            ) from e

    def exchange_code(
        self, auth_code: str, state: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Exchange authorization code for tokens.
        """
        try:
            token_data = {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "code": auth_code,
                "grant_type": "authorization_code",
                "redirect_uri": self.redirect_uri,
            }
            response = self._make_request(
                method="POST",
                url=self.token_url,
                data=token_data,
            )
            self._validate_token_response(response)
            return response
        except Exception as e:
            logger.error(f"Google token exchange failed: {str(e)}", exc_info=True)
            if isinstance(e, (ProviderError, ValidationError)):
                raise
            raise ProviderError(
                f"Google token exchange failed: {str(e)}", "google"
            ) from e

    async def exchange_code_async(
        self, auth_code: str, state: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Exchange authorization code for tokens (async).
        """
        try:
            token_data = {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "code": auth_code,
                "grant_type": "authorization_code",
                "redirect_uri": self.redirect_uri,
            }
            response = await self._make_request_async(
                method="POST",
                url=self.token_url,
                data=token_data,
            )
            self._validate_token_response(response)
            return response
        except Exception as e:
            logger.error(f"Google async token exchange failed: {str(e)}", exc_info=True)
            if isinstance(e, (ProviderError, ValidationError)):
                raise
            raise ProviderError(
                f"Google async token exchange failed: {str(e)}", "google"
            ) from e

    def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """
        Get user information from Google.
        """
        try:
            headers = {"Authorization": f"Bearer {access_token}"}
            response = self._make_request(
                method="GET",
                url=self.user_info_url,
                headers=headers,
            )
            return self._map_user_data(response)
        except Exception as e:
            logger.error(f"Failed to get Google user info: {str(e)}", exc_info=True)
            if isinstance(e, (ProviderError, ValidationError)):
                raise
            raise ProviderError(
                f"Failed to get Google user info: {str(e)}", "google"
            ) from e

    async def get_user_info_async(self, access_token: str) -> Dict[str, Any]:
        """
        Get user information from Google (async).
        """
        try:
            headers = {"Authorization": f"Bearer {access_token}"}
            response = await self._make_request_async(
                method="GET",
                url=self.user_info_url,
                headers=headers,
            )
            return self._map_user_data(response)
        except Exception as e:
            logger.error(
                f"Failed to get Google user info (async): {str(e)}", exc_info=True
            )
            if isinstance(e, (ProviderError, ValidationError)):
                raise
            raise ProviderError(
                f"Failed to get Google user info: {str(e)}", "google"
            ) from e

    def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """
        Refresh access token using refresh token.
        """
        try:
            token_data = {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
            }
            response = self._make_request(
                method="POST",
                url=self.token_url,
                data=token_data,
            )
            self._validate_token_response(response)
            return response
        except Exception as e:
            logger.error(f"Google token refresh failed: {str(e)}", exc_info=True)
            if isinstance(e, (ProviderError, ValidationError)):
                raise
            raise ProviderError(
                f"Google token refresh failed: {str(e)}", "google"
            ) from e

    async def refresh_token_async(self, refresh_token: str) -> Dict[str, Any]:
        """
        Refresh access token using refresh token (async).
        """
        try:
            token_data = {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
            }
            response = await self._make_request_async(
                method="POST",
                url=self.token_url,
                data=token_data,
            )
            self._validate_token_response(response)
            return response
        except Exception as e:
            logger.error(f"Google async token refresh failed: {str(e)}", exc_info=True)
            if isinstance(e, (ProviderError, ValidationError)):
                raise
            raise ProviderError(
                f"Google async token refresh failed: {str(e)}", "google"
            ) from e

    def revoke_token(self, token: str) -> bool:
        """
        Revoke access or refresh token.
        """
        try:
            response = self._make_request(
                method="POST",
                url=f"https://oauth2.googleapis.com/revoke?token={token}",
            )
            if response.get("error"):
                logger.error(
                    f"Google token revocation failed: {response.get('error_description')}"
                )
                return False
            return True
        except Exception as e:
            logger.error(f"Google token revocation failed: {str(e)}", exc_info=True)
            return False

    async def revoke_token_async(self, token: str) -> bool:
        """
        Revoke access or refresh token (async).
        """
        try:
            response = await self._make_request_async(
                method="POST",
                url=f"https://oauth2.googleapis.com/revoke?token={token}",
            )
            if response.get("error"):
                logger.error(
                    f"Google async token revocation failed: {response.get('error_description')}"
                )
                return False
            return True
        except Exception as e:
            logger.error(
                f"Google async token revocation failed: {str(e)}", exc_info=True
            )
            return False

    def _map_user_data(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Map Google user data to our standard format.
        """
        if not user_data.get("id"):
            raise ValidationError("User ID missing from Google response")

        return {
            "id": user_data.get("id"),
            "email": user_data.get("email", ""),
            "first_name": user_data.get("given_name", ""),
            "last_name": user_data.get("family_name", ""),
            "name": user_data.get("name", ""),
            "picture": user_data.get("picture", ""),
            "verified_email": user_data.get("verified_email", False),
        }
