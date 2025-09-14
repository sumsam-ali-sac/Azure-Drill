"""
OAuth and social login functionality.
Supports Google, Azure AD, and other OAuth providers.
"""

from .oauth_manager import OAuthManager
from .providers import GoogleProvider, AzureProvider

__all__ = ["OAuthManager", "GoogleProvider", "AzureProvider"]
