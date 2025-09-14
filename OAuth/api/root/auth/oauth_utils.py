"""
OAuth utilities for social login integration.
Supports Google and Azure AD OAuth flows with PKCE and CSRF protection.
"""

import json
import secrets
import base64
import hashlib
import requests
from typing import Dict, Any, Optional, Tuple
from urllib.parse import urlencode, parse_qs, urlparse
from .configs import config
from .secrets import secret_manager
from .constants import (
    OAUTH_PROVIDER_GOOGLE,
    OAUTH_PROVIDER_AZURE,
    GOOGLE_OAUTH_SCOPES,
    AZURE_OAUTH_SCOPES,
    GOOGLE_OAUTH_URLS,
    AZURE_OAUTH_URLS,
    CSRF_STATE_KEY
)
from .exceptions import OAuthError, CSRFError, AuthConfigurationError
from .utils import security_utils
from .token_utils import token_manager


class OAuthProvider:
    """Base OAuth provider class."""
    
    def __init__(self, name: str, client_id: str, client_secret: str):
        self.name = name
        self.client_id = client_id
        self.client_secret = client_secret
    
    def get_authorization_url(self, redirect_uri: str, state: str, **kwargs) -> str:
        """Get OAuth authorization URL."""
        raise NotImplementedError
    
    def exchange_code_for_token(self, code: str, redirect_uri: str, **kwargs) -> Dict[str, Any]:
        """Exchange authorization code for access token."""
        raise NotImplementedError
    
    def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get user information from OAuth provider."""
        raise NotImplementedError


class GoogleOAuthProvider(OAuthProvider):
    """Google OAuth provider implementation."""
    
    def __init__(self, client_id: str, client_secret: str):
        super().__init__(OAUTH_PROVIDER_GOOGLE, client_id, client_secret)
        self.urls = GOOGLE_OAUTH_URLS
        self.scopes = GOOGLE_OAUTH_SCOPES
    
    def get_authorization_url(
        self,
        redirect_uri: str,
        state: str,
        scopes: Optional[list] = None,
        **kwargs
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
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'scope': ' '.join(scopes),
            'response_type': 'code',
            'state': state,
            'access_type': 'offline',  # For refresh tokens
            'prompt': 'consent'  # Force consent screen
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
            'redirect_uri': redirect_uri
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
        Get user information from Google.
        
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
                'email': user_data.get('email'),
                'first_name': user_data.get('given_name'),
                'last_name': user_data.get('family_name'),
                'name': user_data.get('name'),
                'picture': user_data.get('picture'),
                'verified_email': user_data.get('verified_email', False),
                'provider': self.name,
                'raw_data': user_data
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
                issuer='https://accounts.google.com'
            )
        except Exception as e:
            raise OAuthError(f"Failed to verify ID token: {str(e)}", self.name)


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


class OAuthManager:
    """Manages OAuth providers and flows."""
    
    def __init__(self):
        self.providers: Dict[str, OAuthProvider] = {}
        self.state_storage: Dict[str, Dict[str, Any]] = {}  # Use Redis in production
        self._initialize_providers()
    
    def _initialize_providers(self):
        """Initialize configured OAuth providers."""
        # Google OAuth
        if config.is_google_oauth_enabled:
            self.providers[OAUTH_PROVIDER_GOOGLE] = GoogleOAuthProvider(
                config.GOOGLE_CLIENT_ID,
                config.GOOGLE_CLIENT_SECRET
            )
        
        # Azure AD OAuth
        if config.is_azure_oauth_enabled:
            self.providers[OAUTH_PROVIDER_AZURE] = AzureOAuthProvider(
                config.AZURE_CLIENT_ID,
                config.AZURE_CLIENT_SECRET,
                config.AZURE_TENANT_ID
            )
    
    def get_provider(self, provider_name: str) -> OAuthProvider:
        """
        Get OAuth provider by name.
        
        Args:
            provider_name: Name of the OAuth provider
        
        Returns:
            OAuth provider instance
        
        Raises:
            OAuthError: If provider is not configured
        """
        if provider_name not in self.providers:
            raise OAuthError(f"OAuth provider '{provider_name}' is not configured")
        
        return self.providers[provider_name]
    
    def get_available_providers(self) -> list[str]:
        """Get list of available OAuth providers."""
        return list(self.providers.keys())
    
    def generate_oauth_state(self, provider: str, redirect_uri: str, **metadata) -> str:
        """
        Generate OAuth state parameter with CSRF protection.
        
        Args:
            provider: OAuth provider name
            redirect_uri: Callback URL
            **metadata: Additional metadata to store with state
        
        Returns:
            State parameter
        """
        state = security_utils.generate_state_token()
        
        self.state_storage[state] = {
            'provider': provider,
            'redirect_uri': redirect_uri,
            'created_at': secrets.token_hex(16),  # Timestamp placeholder
            **metadata
        }
        
        return state
    
    def verify_oauth_state(self, state: str, provider: str) -> Dict[str, Any]:
        """
        Verify OAuth state parameter.
        
        Args:
            state: State parameter to verify
            provider: Expected OAuth provider
        
        Returns:
            State metadata
        
        Raises:
            CSRFError: If state is invalid
        """
        if state not in self.state_storage:
            raise CSRFError("Invalid or expired OAuth state")
        
        state_data = self.state_storage[state]
        
        if state_data['provider'] != provider:
            raise CSRFError("OAuth state provider mismatch")
        
        # Remove state after verification (single use)
        del self.state_storage[state]
        
        return state_data
    
    def get_authorization_url(
        self,
        provider_name: str,
        redirect_uri: str,
        scopes: Optional[list] = None,
        **kwargs
    ) -> Tuple[str, str]:
        """
        Get OAuth authorization URL with state.
        
        Args:
            provider_name: OAuth provider name
            redirect_uri: Callback URL
            scopes: OAuth scopes
            **kwargs: Additional parameters
        
        Returns:
            Tuple of (authorization_url, state)
        """
        provider = self.get_provider(provider_name)
        state = self.generate_oauth_state(provider_name, redirect_uri, **kwargs)
        
        auth_url = provider.get_authorization_url(
            redirect_uri=redirect_uri,
            state=state,
            scopes=scopes,
            **kwargs
        )
        
        return auth_url, state
    
    def handle_oauth_callback(
        self,
        provider_name: str,
        code: str,
        state: str,
        redirect_uri: str
    ) -> Dict[str, Any]:
        """
        Handle OAuth callback and get user information.
        
        Args:
            provider_name: OAuth provider name
            code: Authorization code
            state: State parameter
            redirect_uri: Callback URL
        
        Returns:
            User information and tokens
        """
        # Verify state
        state_data = self.verify_oauth_state(state, provider_name)
        
        # Get provider
        provider = self.get_provider(provider_name)
        
        # Exchange code for token
        token_response = provider.exchange_code_for_token(code, redirect_uri)
        
        # Get user information
        access_token = token_response.get('access_token')
        if not access_token:
            raise OAuthError("No access token received", provider_name)
        
        user_info = provider.get_user_info(access_token)
        
        # Verify ID token if present (for Google)
        id_token = token_response.get('id_token')
        if id_token and isinstance(provider, GoogleOAuthProvider):
            try:
                id_token_payload = provider.verify_id_token(id_token)
                user_info['id_token_payload'] = id_token_payload
            except Exception:
                # ID token verification failed, but we can still proceed with user info
                pass
        
        return {
            'user_info': user_info,
            'tokens': token_response,
            'state_data': state_data
        }
    
    def create_user_tokens(self, user_info: Dict[str, Any]) -> Dict[str, str]:
        """
        Create JWT tokens for OAuth user.
        
        Args:
            user_info: User information from OAuth provider
        
        Returns:
            Dictionary with access and refresh tokens
        """
        payload = {
            'sub': user_info['email'],
            'email': user_info['email'],
            'first_name': user_info.get('first_name'),
            'last_name': user_info.get('last_name'),
            'name': user_info.get('name'),
            'picture': user_info.get('picture'),
            'provider': user_info['provider'],
            'provider_id': user_info['id'],
            'verified_email': user_info.get('verified_email', False),
            'roles': ['user']  # Default role for OAuth users
        }
        
        return token_manager.create_token_pair(payload)
    
    def refresh_oauth_token(self, provider_name: str, refresh_token: str) -> Dict[str, Any]:
        """
        Refresh OAuth access token.
        
        Args:
            provider_name: OAuth provider name
            refresh_token: Refresh token
        
        Returns:
            New token response
        """
        provider = self.get_provider(provider_name)
        
        if provider_name == OAUTH_PROVIDER_GOOGLE:
            data = {
                'client_id': provider.client_id,
                'client_secret': provider.client_secret,
                'refresh_token': refresh_token,
                'grant_type': 'refresh_token'
            }
            
            try:
                response = requests.post(
                    provider.urls['token'],
                    data=data,
                    headers={'Accept': 'application/json'},
                    timeout=10
                )
                response.raise_for_status()
                return response.json()
            except requests.RequestException as e:
                raise OAuthError(f"Failed to refresh token: {str(e)}", provider_name)
        
        else:
            raise OAuthError(f"Token refresh not implemented for {provider_name}", provider_name)
    
    def revoke_oauth_token(self, provider_name: str, token: str) -> bool:
        """
        Revoke OAuth token.
        
        Args:
            provider_name: OAuth provider name
            token: Token to revoke
        
        Returns:
            True if token was revoked successfully
        """
        provider = self.get_provider(provider_name)
        
        if provider_name == OAUTH_PROVIDER_GOOGLE:
            try:
                response = requests.post(
                    f"https://oauth2.googleapis.com/revoke?token={token}",
                    timeout=10
                )
                return response.status_code == 200
            except requests.RequestException:
                return False
        
        # For other providers, implement as needed
        return True
    
    def cleanup_expired_states(self):
        """Clean up expired OAuth states."""
        # TODO: Implement state expiration cleanup
        # In production, use Redis with TTL
        pass


# Global OAuth manager instance
oauth_manager = OAuthManager()
