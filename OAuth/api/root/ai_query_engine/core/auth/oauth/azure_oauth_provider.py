"""
Azure AD OAuth provider implementation.
"""

import requests
from typing import Dict, Any, Optional
from urllib.parse import urlencode

from auth.oauth.oauth_provider import OAuthProvider
from auth.constants import (
    OAUTH_PROVIDER_AZURE,
    AZURE_OAUTH_SCOPES,
    AZURE_OAUTH_URLS
)
from auth.exceptions import OAuthError


class AzureOAuthProvider(OAuthProvider):
    """Azure AD OAuth provider implementation."""
    
    def __init__(self, client_id: str, client_secret: str, tenant_id: str):
        super().__init__(OAUTH_PROVIDER_AZURE, client_id, client_secret)
        self.tenant_id = tenant_id
        self.urls = {
            key: url.format(tenant_id=tenant_id) 
            for key, url in AZURE_OAUTH_URLS.items()
        }
        self.scopes = AZURE_OAUTH_SCOPES
    
    def get_authorization_url(
        self,
        redirect_uri: str,
        state: str,
        scopes: Optional[list] = None,
        **kwargs
    ) -> str:
        """
        Get Azure AD OAuth authorization URL.
        
        Args:
            redirect_uri: Callback URL
            state: CSRF state parameter
            scopes: OAuth scopes (defaults to configured scopes)
        
        Returns:
            Authorization URL
        """
        scopes = scopes or self.scopes
        
        params = {
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'scope': ' '.join(scopes),
            'response_type': 'code',
            'state': state,
            'response_mode': 'query'
        }
        
        return f"{self.urls['authorize']}?{urlencode(params)}"
    
    def exchange_code_for_token(
        self,
        code: str,
        redirect_uri: str,
        **kwargs
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
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': redirect_uri,
            'scope': ' '.join(self.scopes)
        }
        
        try:
            response = requests.post(
                self.urls['token'],
                data=data,
                headers={'Accept': 'application/json'},
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            raise OAuthError(f"Failed to exchange code for token: {str(e)}", self.name)
    
    def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """
        Get user information from Microsoft Graph.
        
        Args:
            access_token: OAuth access token
        
        Returns:
            User information dictionary
        """
        headers = {'Authorization': f'Bearer {access_token}'}
        
        try:
            response = requests.get(
                self.urls['userinfo'],
                headers=headers,
                timeout=10
            )
            response.raise_for_status()
            user_data = response.json()
            
            # Normalize user data
            return {
                'id': user_data.get('id'),
                'email': user_data.get('mail') or user_data.get('userPrincipalName'),
                'first_name': user_data.get('givenName'),
                'last_name': user_data.get('surname'),
                'name': user_data.get('displayName'),
                'picture': None,  # Would need separate Graph API call
                'verified_email': True,  # Azure AD emails are verified
                'provider': self.name,
                'raw_data': user_data
            }
        except requests.RequestException as e:
            raise OAuthError(f"Failed to get user info: {str(e)}", self.name)
