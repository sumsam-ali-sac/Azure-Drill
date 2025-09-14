"""
OAuth and social login functionality.
Supports Google, Azure AD, and other OAuth providers.
"""

from auth.oauth.google_oauth_provider import GoogleOAuthProvider
from auth.oauth.azure_oauth_provider import AzureOAuthProvider
from auth.oauth.oauth_manager import OAuthManager

__all__ = ["OAuthManager", "GoogleOAuthProvider", "AzureOAuthProvider"]
