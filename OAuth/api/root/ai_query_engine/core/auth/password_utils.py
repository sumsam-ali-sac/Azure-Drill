"""
Refactored to use absolute imports and removed multiple classes
Updated to import password classes from their dedicated modules.
"""

from auth.password.password_manager import PasswordManager, password_manager
from auth.password.password_policy import PasswordPolicy, password_policy

__all__ = [
    'PasswordManager',
    'PasswordPolicy', 
    'password_manager',
    'password_policy'
]
