"""
Core authentication functionality.
Contains the main AuthManager and core authentication logic.
"""

from .auth_manager import AuthManager
from .flows import AuthFlows

__all__ = ["AuthManager", "AuthFlows"]
