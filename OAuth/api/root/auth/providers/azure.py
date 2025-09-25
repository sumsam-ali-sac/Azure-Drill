"""
Azure AD OAuth provider implementation using MSAL.
"""

from typing import Dict, Any, Optional
import msal
from root.auth.providers.base import BaseOAuthProvider
from root.auth.config import config
from root.auth.exceptions.auth_exceptions import ProviderError, ValidationError
import logging
import asyncio

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
            logger.error("Azure OAuth credentials not configured")
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
        if state is not None and not isinstance(state, str):
            logger.error("Invalid state type provided for auth URL")
            raise ValidationError("State must be a string or None")
        try:
            auth_url = self.msal_app.get_authorization_request_url(
                scopes=self.scopes, redirect_uri=self.redirect_uri, state=state
            )
            logger.debug(f"Generated auth URL for Azure with state: {state}")
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
        if not isinstance(auth_code, str):
            logger.error("Invalid auth code type provided for token exchange")
            raise ValidationError("Auth code must be a string")
        if state is not None and not isinstance(state, str):
            logger.error("Invalid state type provided for token exchange")
            raise ValidationError("State must be a string or None")
        try:
            result = self.msal_app.acquire_token_by_authorization_code(
                code=auth_code, scopes=self.scopes, redirect_uri=self.redirect_uri
            )
            self._validate_token_response(result)
            logger.info(f"Successfully exchanged auth code for tokens")
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
        if not isinstance(auth_code, str):
            logger.error("Invalid auth code type provided for async token exchange")
            raise ValidationError("Auth code must be a string")
        if state is not None and not isinstance(state, str):
            logger.error("Invalid state type provided for async token exchange")
            raise ValidationError("State must be a string or None")
        try:
            # MSAL is sync, so run in default executor to avoid blocking
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.msal_app.acquire_token_by_authorization_code(
                    code=auth_code, scopes=self.scopes, redirect_uri=self.redirect_uri
                ),
            )
            self._validate_token_response(result)
            logger.info(f"Successfully exchanged auth code for tokens (async)")
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
        if not isinstance(access_token, str):
            logger.error("Invalid access token type provided for user info")
            raise ValidationError("Access token must be a string")
        try:
            headers = {"Authorization": f"Bearer {access_token}"}
            response = self._make_request(
                method="GET", url="https://graph.microsoft.com/v1.0/me", headers=headers
            )
            user_data = self._map_user_data(response)
            logger.info(f"Retrieved user info for Azure user ID: {user_data.get('id')}")
            return user_data
        except Exception as e:
            logger.error(f"Failed to get Azure user info: {str(e)}", exc_info=True)
            raise ProviderError(
                f"Failed to get Azure user info: {str(e)}", "azure"
            ) from e

    async def get_user_info_async(self, access_token: str) -> Dict[str, Any]:
        """
        Get user information from Azure AD (async).
        """
        if not isinstance(access_token, str):
            logger.error("Invalid access token type provided for async user info")
            raise ValidationError("Access token must be a string")
        try:
            headers = {"Authorization": f"Bearer {access_token}"}
            response = await self._make_request_async(
                method="GET", url="https://graph.microsoft.com/v1.0/me", headers=headers
            )
            user_data = self._map_user_data(response)
            logger.info(
                f"Retrieved user info (async) for Azure user ID: {user_data.get('id')}"
            )
            return user_data
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
        if not isinstance(refresh_token, str):
            logger.error("Invalid refresh token type provided for token refresh")
            raise ValidationError("Refresh token must be a string")
        try:
            result = self.msal_app.acquire_token_by_refresh_token(
                refresh_token=refresh_token, scopes=self.scopes
            )
            self._validate_token_response(result)
            logger.info("Successfully refreshed Azure access token")
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
        if not isinstance(refresh_token, str):
            logger.error("Invalid refresh token type provided for async token refresh")
            raise ValidationError("Refresh token must be a string")
        try:
            # MSAL is sync, so run in default executor to avoid blocking
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.msal_app.acquire_token_by_refresh_token(
                    refresh_token=refresh_token, scopes=self.scopes
                ),
            )
            self._validate_token_response(result)
            logger.info("Successfully refreshed Azure access token (async)")
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
            logger.info(f"Retrieved tenant info for tenant ID: {self.tenant_id}")
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
            logger.info(
                f"Retrieved tenant info (async) for tenant ID: {self.tenant_id}"
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
        if not isinstance(user_data, dict):
            logger.error("Invalid user data type provided for mapping")
            raise ValidationError("User data must be a dictionary")
        if not user_data.get("id"):
            logger.error("User ID missing from Azure AD response")
            raise ValidationError("User ID missing from Azure AD response")

        mapped_data = {
            "id": user_data.get("id"),
            "email": user_data.get("mail") or user_data.get("userPrincipalName", ""),
            "first_name": user_data.get("givenName", ""),
            "last_name": user_data.get("surname", ""),
            "name": user_data.get("displayName", ""),
            "job_title": user_data.get("jobTitle", ""),
            "office_location": user_data.get("officeLocation", ""),
        }
        # Log missing optional fields for debugging
        optional_fields = [
            "mail",
            "userPrincipalName",
            "givenName",
            "surname",
            "displayName",
            "jobTitle",
            "officeLocation",
        ]
        missing_fields = [
            field for field in optional_fields if not user_data.get(field)
        ]
        if missing_fields:
            logger.debug(
                f"Missing optional fields in Azure user data: {', '.join(missing_fields)}"
            )
        return {k: v for k, v in mapped_data.items() if v is not None}
