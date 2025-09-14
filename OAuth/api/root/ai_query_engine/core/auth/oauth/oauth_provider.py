"""
Base OAuth provider class.
"""

from typing import Dict, Any


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
