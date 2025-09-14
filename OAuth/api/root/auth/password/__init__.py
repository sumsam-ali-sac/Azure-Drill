"""Password management module."""

from auth.password.password_manager import PasswordManager
from auth.password.password_policy import PasswordPolicy

# Global instances
password_manager = PasswordManager()
password_policy = PasswordPolicy()

__all__ = [
    'PasswordManager',
    'PasswordPolicy',
    'password_manager',
    'password_policy'
]
