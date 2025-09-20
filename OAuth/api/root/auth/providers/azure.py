"""
Azure AD OAuth provider implementation using MSAL.
"""

from typing import Dict, Any, Optional
from urllib.parse import urlencode
import httpx
import msal
from auth.providers.base import BaseOAuthProvider
from auth.config import config
from auth.exceptions.auth_exceptions import ProviderError, ValidationError
import logging

# Configure logging
logger = logging.getLogger(__name__)


class AzureOAuthProvider(BaseOAuthProvider):
    """
    Azure AD OAuth provider implementation using MSAL.

    Handles Azure AD OAuth2 authentication flow with proper ID token verification.
    """

    def __init__(self):
        """Initialize Azure OAuth provider with MSAL."""
        self.client_id = config.AZURE_CLIENT_ID
        self.client_secret = config.AZURE_CLIENT_SECRET
        self.tenant_id = config.AZURE_TENANT_ID or "common"
        self.redirect_uri = config.AZURE_REDIRECT_URI
        self.scopes = ["openid", "profile", "email", "User.Read"]

        if not all([self.client_id, self.client_secret, self.redirect_uri]):
            raise ProviderError("Azure OAuth credentials not configured", "azure")

        authority = f"https://login.microsoftonline.com/{self.tenant_id}"
        self.msal_app = msal.ConfidentialClientApplication(
            client_id=self.client_id,
            client_credential=self.client_secret,
            authority=authority,
        )

    @property
    def provider_name(self) -> str:
        """Get the name of the OAuth provider."""
        return "azure"

    def get_auth_url(self, state: Optional[str] = None) -> str:
        """
        Get Azure AD OAuth authorization URL using MSAL.
        """
        try:
            auth_url = self.msal_app.get_authorization_request_url(
                scopes=self.scopes, redirect_uri=self.redirect_uri, state=state
            )
            return auth_url
        except Exception as e:
            logger.error(f"Failed to generate auth URL: {str(e)}", exc_info=True)
            raise ProviderError(
                f"Failed to generate auth URL: {str(e)}", "azure"
            ) from e

    def exchange_code(
        self, auth_code: str, state: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Exchange authorization code for tokens using MSAL.
        """
        try:
            result = self.msal_app.acquire_token_by_authorization_code(
                code=auth_code, scopes=self.scopes, redirect_uri=self.redirect_uri
            )
            self._validate_token_response(result)
            return result
        except Exception as e:
            logger.error(f"Azure token exchange failed: {str(e)}", exc_info=True)
            if isinstance(e, ProviderError):
                raise
            raise ProviderError(
                f"Azure token exchange failed: {str(e)}", "azure"
            ) from e

    async def exchange_code_async(
        self, auth_code: str, state: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Exchange authorization code for tokens using MSAL (async).
        """
        try:
            # MSAL doesn't have async support, so we wrap the sync call in an async context
            # In production, consider using a thread pool for I/O-bound operations
            result = await self._make_request_async(
                method="POST",
                url=f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token",
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "code": auth_code,
                    "grant_type": "authorization_code",
                    "redirect_uri": self.redirect_uri,
                    "scope": " ".join(self.scopes),
                },
            )
            self._validate_token_response(result)
            return result
        except Exception as e:
            logger.error(f"Azure async token exchange failed: {str(e)}", exc_info=True)
            if isinstance(e, ProviderError):
                raise
            raise ProviderError(
                f"Azure async token exchange failed: {str(e)}", "azure"
            ) from e

    def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """
        Get user information from Azure AD.
        """
        try:
            headers = {"Authorization": f"Bearer {access_token}"}
            response = self._make_request(
                method="GET", url="https://graph.microsoft.com/v1.0/me", headers=headers
            )
            return self._map_user_data(response)
        except Exception as e:
            logger.error(f"Failed to get Azure user info: {str(e)}", exc_info=True)
            raise ProviderError(
                f"Failed to get Azure user info: {str(e)}", "azure"
            ) from e

    async def get_user_info_async(self, access_token: str) -> Dict[str, Any]:
        """
        Get user information from Azure AD (async).
        """
        try:
            headers = {"Authorization": f"Bearer {access_token}"}
            response = await self._make_request_async(
                method="GET", url="https://graph.microsoft.com/v1.0/me", headers=headers
            )
            return self._map_user_data(response)
        except Exception as e:
            logger.error(
                f"Failed to get Azure user info (async): {str(e)}", exc_info=True
            )
            raise ProviderError(
                f"Failed to get Azure user info: {str(e)}", "azure"
            ) from e

    def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """
        Refresh access token using MSAL.
        """
        try:
            result = self.msal_app.acquire_token_by_refresh_token(
                refresh_token=refresh_token, scopes=self.scopes
            )
            self._validate_token_response(result)
            return result
        except Exception as e:
            logger.error(f"Azure token refresh failed: {str(e)}", exc_info=True)
            if isinstance(e, ProviderError):
                raise
            raise ProviderError(f"Azure token refresh failed: {str(e)}", "azure") from e

    async def refresh_token_async(self, refresh_token: str) -> Dict[str, Any]:
        """
        Refresh access token using MSAL (async).
        """
        try:
            result = await self._make_request_async(
                method="POST",
                url=f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token",
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "refresh_token": refresh_token,
                    "grant_type": "refresh_token",
                    "scope": " ".join(self.scopes),
                },
            )
            self._validate_token_response(result)
            return result
        except Exception as e:
            logger.error(f"Azure async token refresh failed: {str(e)}", exc_info=True)
            if isinstance(e, ProviderError):
                raise
            raise ProviderError(
                f"Azure async token refresh failed: {str(e)}", "azure"
            ) from e

    def get_tenant_info(self) -> Dict[str, Any]:
        """
        Get tenant information (for multi-tenant applications).
        """
        try:
            response = self._make_request(
                method="GET",
                url=f"https://login.microsoftonline.com/{self.tenant_id}/v2.0/.well-known/openid_configuration",
            )
            return response
        except Exception as e:
            logger.error(f"Failed to get Azure tenant info: {str(e)}", exc_info=True)
            raise ProviderError(
                f"Failed to get Azure tenant info: {str(e)}", "azure"
            ) from e

    async def get_tenant_info_async(self) -> Dict[str, Any]:
        """
        Get tenant information (for multi-tenant applications, async).
        """
        try:
            response = await self._make_request_async(
                method="GET",
                url=f"https://login.microsoftonline.com/{self.tenant_id}/v2.0/.well-known/openid_configuration",
            )
            return response
        except Exception as e:
            logger.error(
                f"Failed to get Azure tenant info (async): {str(e)}", exc_info=True
            )
            raise ProviderError(
                f"Failed to get Azure tenant info: {str(e)}", "azure"
            ) from e

    def _map_user_data(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Map Azure user data to our standard format.
        """
        if not user_data.get("id"):
            raise ValidationError("User ID missing from Azure AD response")

        return {
            "id": user_data.get("id"),
            "email": user_data.get("mail") or user_data.get("userPrincipalName", ""),
            "first_name": user_data.get("givenName", ""),
            "last_name": user_data.get("surname", ""),
            "name": user_data.get("displayName", ""),
            "job_title": user_data.get("jobTitle", ""),
            "office_location": user_data.get("officeLocation", ""),
        }
