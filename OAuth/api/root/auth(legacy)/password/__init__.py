"""Password management module."""

from root.authpassword.password_manager import PasswordManager
from root.authpassword.password_policy import PasswordPolicy

# Global instances
password_manager = PasswordManager()
password_policy = PasswordPolicy()

__all__ = ["PasswordManager", "PasswordPolicy", "password_manager", "password_policy"]
