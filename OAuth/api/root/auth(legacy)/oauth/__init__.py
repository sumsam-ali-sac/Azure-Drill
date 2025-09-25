"""
OAuth and social login functionality.
Supports Google, Azure AD, and other OAuth providers.
"""

from root.authoroot.authgoogle_oauth_provider import GoogleOAuthProvider
from root.authoroot.authazure_oauth_provider import AzureOAuthProvider
from root.authoroot.authoauth_manager import OAuthManager

__all__ = ["OAuthManager", "GoogleOAuthProvider", "AzureOAuthProvider"]
