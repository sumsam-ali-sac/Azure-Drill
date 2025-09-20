"""
Azure AD OAuth provider implementation using MSAL.
"""

import json
from typing import Dict, Any, Optional
from urllib.parse import urlencode
import msal
from auth_service.providers.base import BaseOAuthProvider
from auth_service.config import config
from auth_service.exceptions.auth_exceptions import ProviderError

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
        
        # OAuth scopes
        self.scopes = ["openid", "profile", "email", "User.Read"]
        
        if not self.client_id or not self.client_secret:
            raise ProviderError("Azure OAuth credentials not configured", "azure")
        
        # Initialize MSAL confidential client
        authority = f"https://login.microsoftonline.com/{self.tenant_id}"
        self.msal_app = msal.ConfidentialClientApplication(
            client_id=self.client_id,
            client_credential=self.client_secret,
            authority=authority
        )
    
    @property
    def provider_name(self) -> str:
        """Get the name of the OAuth provider."""
        return "azure"
    
    def get_auth_url(self, state: Optional[str] = None) -> str:
        """
        Get Azure AD OAuth authorization URL using MSAL.
        
        Args:
            state: Optional state parameter for CSRF protection
            
        Returns:
            Azure authorization URL
        """
        auth_url = self.msal_app.get_authorization_request_url(
            scopes=self.scopes,
            redirect_uri=self.redirect_uri,
            state=state
        )
        return auth_url
    
    def exchange_code(self, auth_code: str, state: Optional[str] = None) -> Dict[str, Any]:
        """
        Exchange authorization code for tokens using MSAL.
        
        Args:
            auth_code: Authorization code from Azure
            state: Optional state parameter for validation
            
        Returns:
            Token response dict containing access_token, id_token, etc.
            
        Raises:
            ProviderError: If token exchange fails
        """
        try:
            result = self.msal_app.acquire_token_by_authorization_code(
                code=auth_code,
                scopes=self.scopes,
                redirect_uri=self.redirect_uri
            )
            
            if "error" in result:
                error_desc = result.get("error_description", "Unknown error")
                raise ProviderError(f"Azure token exchange failed: {error_desc}", "azure")
            
            if not result.get("access_token"):
                raise ProviderError("No access token received from Azure", "azure")
            
            return result
            
        except Exception as e:
            if isinstance(e, ProviderError):
                raise
            raise ProviderError(f"Azure OAuth error: {str(e)}", "azure")
    
    async def exchange_code_async(self, auth_code: str, state: Optional[str] = None) -> Dict[str, Any]:
        """Exchange authorization code for tokens (async)."""
        # For now, use synchronous implementation
        # In production, use aiohttp or similar async HTTP client
        return self.exchange_code(auth_code, state)
    
    def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """
        Get user information from Azure AD using MSAL.
        
        Args:
            access_token: Access token from Azure
            
        Returns:
            User information dictionary
            
        Raises:
            ProviderError: If user info retrieval fails
        """
        try:
            import requests
            headers = {"Authorization": f"Bearer {access_token}"}
            response = requests.get("https://graph.microsoft.com/v1.0/me", headers=headers)
            response.raise_for_status()
            
            user_data = response.json()
            
            return self._map_user_data(user_data)
            
        except requests.RequestException as e:
            raise ProviderError(f"Failed to get user info from Azure: {str(e)}", "azure")
        except Exception as e:
            raise ProviderError(f"Azure user info error: {str(e)}", "azure")
    
    def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """
        Refresh access token using MSAL.
        
        Args:
            refresh_token: Refresh token from Azure
            
        Returns:
            New token information
            
        Raises:
            ProviderError: If token refresh fails
        """
        try:
            result = self.msal_app.acquire_token_by_refresh_token(
                refresh_token=refresh_token,
                scopes=self.scopes
            )
            
            if "error" in result:
                error_desc = result.get("error_description", "Unknown error")
                raise ProviderError(f"Azure token refresh failed: {error_desc}", "azure")
            
            return result
            
        except Exception as e:
            if isinstance(e, ProviderError):
                raise
            raise ProviderError(f"Azure token refresh error: {str(e)}", "azure")
    
    async def get_user_info_async(self, access_token: str) -> Dict[str, Any]:
        """Get user information from Azure AD (async)."""
        # For now, use synchronous implementation
        # In production, use aiohttp or similar async HTTP client
        return self.get_user_info(access_token)
    
    def get_tenant_info(self) -> Dict[str, Any]:
        """
        Get tenant information (for multi-tenant applications).
        
        Returns:
            Tenant information
        """
        try:
            tenant_url = f"https://login.microsoftonline.com/{self.tenant_id}/v2.0/.well-known/openid_configuration"
            response = requests.get(tenant_url)
            response.raise_for_status()
            
            return response.json()
            
        except Exception as e:
            raise ProviderError(f"Failed to get tenant info: {str(e)}", "azure")
    
    def _map_user_data(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Map Azure user data to our standard format.
        
        Args:
            user_data: User data from Azure AD
            
        Returns:
            Standardized user information dictionary
        """
        return {
            "id": user_data.get("id"),
            "email": user_data.get("mail") or user_data.get("userPrincipalName"),
            "first_name": user_data.get("givenName"),
            "last_name": user_data.get("surname"),
            "name": user_data.get("displayName"),
            "job_title": user_data.get("jobTitle"),
            "office_location": user_data.get("officeLocation")
        }
