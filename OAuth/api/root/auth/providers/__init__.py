"""
OAuth providers module.
"""

from .google import GoogleOAuthProvider
from .azure import AzureOAuthProvider

__all__ = ["GoogleOAuthProvider", "AzureOAuthProvider"]
