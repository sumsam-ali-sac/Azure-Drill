"""
Google OAuth provider implementation.
"""

from typing import Dict, Any, Optional
from urllib.parse import urlencode
from root.auth.providers.base import BaseOAuthProvider
from root.auth.config import config
from root.auth.exceptions.auth_exceptions import ProviderError, ValidationError
import logging

# Configure logging
logger = logging.getLogger(__name__)


class GoogleOAuthProvider(BaseOAuthProvider):
    """
    Google OAuth provider implementation.

    Handles Google OAuth2 authentication flow with proper token handling and user info mapping.
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
            logger.error("Google OAuth credentials not configured")
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
            Authorization URL as a string

        Raises:
            ValidationError: If state is invalid
            ProviderError: If URL generation fails
        """
        if state is not None and (not isinstance(state, str) or not state.strip()):
            logger.error("Invalid state parameter provided")
            raise ValidationError("State must be a non-empty string or None")
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
            auth_url = f"{self.auth_url}?{urlencode(params)}"
            logger.debug(f"Generated auth URL for Google with state: {state}")
            return auth_url
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

        Args:
            auth_code: Authorization code from Google
            state: Optional state parameter for validation

        Returns:
            Token response dict containing access_token, id_token, refresh_token, etc.

        Raises:
            ValidationError: If auth_code or state is invalid
            ProviderError: If token exchange fails
        """
        if not isinstance(auth_code, str) or not auth_code.strip():
            logger.error("Invalid authorization code provided")
            raise ValidationError("Authorization code must be a non-empty string")
        if state is not None and (not isinstance(state, str) or not state.strip()):
            logger.error("Invalid state parameter provided")
            raise ValidationError("State must be a non-empty string or None")
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
            logger.info("Successfully exchanged auth code for tokens")
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

        Args:
            auth_code: Authorization code from Google
            state: Optional state parameter for validation

        Returns:
            Token response dict containing access_token, id_token, refresh_token, etc.

        Raises:
            ValidationError: If auth_code or state is invalid
            ProviderError: If token exchange fails
        """
        if not isinstance(auth_code, str) or not auth_code.strip():
            logger.error("Invalid authorization code provided")
            raise ValidationError("Authorization code must be a non-empty string")
        if state is not None and (not isinstance(state, str) or not state.strip()):
            logger.error("Invalid state parameter provided")
            raise ValidationError("State must be a non-empty string or None")
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
            logger.info("Successfully exchanged auth code for tokens (async)")
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

        Args:
            access_token: Access token from Google

        Returns:
            User information dictionary with keys: id, email, first_name, last_name, name, picture, verified_email

        Raises:
            ValidationError: If access_token is invalid
            ProviderError: If user info retrieval fails
        """
        if not isinstance(access_token, str) or not access_token.strip():
            logger.error("Invalid access token provided")
            raise ValidationError("Access token must be a non-empty string")
        try:
            headers = {"Authorization": f"Bearer {access_token}"}
            response = self._make_request(
                method="GET",
                url=self.user_info_url,
                headers=headers,
            )
            user_data = self._map_user_data(response)
            logger.info(
                f"Retrieved user info for Google user ID: {user_data.get('id')}"
            )
            return user_data
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

        Args:
            access_token: Access token from Google

        Returns:
            User information dictionary with keys: id, email, first_name, last_name, name, picture, verified_email

        Raises:
            ValidationError: If access_token is invalid
            ProviderError: If user info retrieval fails
        """
        if not isinstance(access_token, str) or not access_token.strip():
            logger.error("Invalid access token provided")
            raise ValidationError("Access token must be a non-empty string")
        try:
            headers = {"Authorization": f"Bearer {access_token}"}
            response = await self._make_request_async(
                method="GET",
                url=self.user_info_url,
                headers=headers,
            )
            user_data = self._map_user_data(response)
            logger.info(
                f"Retrieved user info (async) for Google user ID: {user_data.get('id')}"
            )
            return user_data
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

        Args:
            refresh_token: Refresh token from Google

        Returns:
            Token response dict containing access_token, etc.

        Raises:
            ValidationError: If refresh_token is invalid
            ProviderError: If token refresh fails
        """
        if not isinstance(refresh_token, str) or not refresh_token.strip():
            logger.error("Invalid refresh token provided")
            raise ValidationError("Refresh token must be a non-empty string")
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
            logger.info("Successfully refreshed Google access token")
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

        Args:
            refresh_token: Refresh token from Google

        Returns:
            Token response dict containing access_token, etc.

        Raises:
            ValidationError: If refresh_token is invalid
            ProviderError: If token refresh fails
        """
        if not isinstance(refresh_token, str) or not refresh_token.strip():
            logger.error("Invalid refresh token provided")
            raise ValidationError("Refresh token must be a non-empty string")
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
            logger.info("Successfully refreshed Google access token (async)")
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

        Args:
            token: Access or refresh token to revoke

        Returns:
            True if revocation succeeded, False otherwise

        Raises:
            ValidationError: If token is invalid
            ProviderError: If token revocation fails
        """
        if not isinstance(token, str) or not token.strip():
            logger.error("Invalid token provided for revocation")
            raise ValidationError("Token must be a non-empty string")
        try:
            response = self._make_request(
                method="POST",
                url=f"https://oauth2.googleapis.com/revoke?token={token}",
            )
            if response.get("error"):
                error_desc = response.get("error_description", "Unknown error")
                logger.error(f"Google token revocation failed: {error_desc}")
                raise ProviderError(f"Token revocation failed: {error_desc}", "google")
            logger.info("Successfully revoked Google token")
            return True
        except Exception as e:
            logger.error(f"Google token revocation failed: {str(e)}", exc_info=True)
            if isinstance(e, (ProviderError, ValidationError)):
                raise
            raise ProviderError(
                f"Google token revocation failed: {str(e)}", "google"
            ) from e

    async def revoke_token_async(self, token: str) -> bool:
        """
        Revoke access or refresh token (async).

        Args:
            token: Access or refresh token to revoke

        Returns:
            True if revocation succeeded, False otherwise

        Raises:
            ValidationError: If token is invalid
            ProviderError: If token revocation fails
        """
        if not isinstance(token, str) or not token.strip():
            logger.error("Invalid token provided for async revocation")
            raise ValidationError("Token must be a non-empty string")
        try:
            response = await self._make_request_async(
                method="POST",
                url=f"https://oauth2.googleapis.com/revoke?token={token}",
            )
            if response.get("error"):
                error_desc = response.get("error_description", "Unknown error")
                logger.error(f"Google async token revocation failed: {error_desc}")
                raise ProviderError(f"Token revocation failed: {error_desc}", "google")
            logger.info("Successfully revoked Google token (async)")
            return True
        except Exception as e:
            logger.error(
                f"Google async token revocation failed: {str(e)}", exc_info=True
            )
            if isinstance(e, (ProviderError, ValidationError)):
                raise
            raise ProviderError(
                f"Google async token revocation failed: {str(e)}", "google"
            ) from e

    def _map_user_data(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Map Google user data to our standard format.

        Args:
            user_data: Raw user data from Google

        Returns:
            Standardized user data with keys: id, email, first_name, last_name, name, picture, verified_email

        Raises:
            ValidationError: If user_data is invalid or missing required fields
        """
        if not isinstance(user_data, dict):
            logger.error("Invalid user data type provided")
            raise ValidationError("User data must be a dictionary")
        if not user_data.get("id"):
            logger.error("User ID missing from Google response")
            raise ValidationError("User ID missing from Google response")

        mapped_data = {
            "id": user_data.get("id"),
            "email": user_data.get("email", ""),
            "first_name": user_data.get("given_name", ""),
            "last_name": user_data.get("family_name", ""),
            "name": user_data.get("name", ""),
            "picture": user_data.get("picture", ""),
            "verified_email": user_data.get("verified_email", False),
        }
        # Log missing optional fields for debugging
        optional_fields = [
            "email",
            "given_name",
            "family_name",
            "name",
            "picture",
            "verified_email",
        ]
        missing_fields = [
            field for field in optional_fields if not user_data.get(field)
        ]
        if missing_fields:
            logger.debug(
                f"Missing optional fields in Google user data: {', '.join(missing_fields)}"
            )
        return {k: v for k, v in mapped_data.items() if v is not None}
