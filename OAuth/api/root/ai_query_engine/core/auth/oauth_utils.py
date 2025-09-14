"""
Refactored to use absolute imports and removed multiple classes
Updated to import OAuth classes from their dedicated modules.
"""

from auth.oauth.oauth_provider import OAuthProvider
from auth.oauth.google_oauth_provider import GoogleOAuthProvider
from auth.oauth.azure_oauth_provider import AzureOAuthProvider
from auth.oauth.oauth_manager import OAuthManager, oauth_manager

__all__ = [
    'OAuthProvider',
    'GoogleOAuthProvider',
    'AzureOAuthProvider', 
    'OAuthManager',
    'oauth_manager'
]
