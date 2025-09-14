"""
Refactored to use absolute imports and removed multiple classes
Updated to import RBAC classes from their dedicated modules.
"""

from typing import List, Optional

from auth.rbac.rbac_manager import RBACManager
from auth.constants import ROLE_ADMIN, ROLE_PERMISSIONS
from auth.exceptions import InsufficientPermissionsError

# Convenience functions for common permission checks
def has_permission(
    user_roles: List[str],
    required_permission: str,
    rbac_manager: Optional[RBACManager] = None
) -> bool:
    """
    Simple permission check using role names.
    
    Args:
        user_roles: List of user's role names
        required_permission: Required permission string
        rbac_manager: RBAC manager instance
    
    Returns:
        True if user has permission
    """
    if not rbac_manager:
        rbac_manager = rbac_manager_instance
    
    # Check if user has admin role (admin has all permissions)
    if ROLE_ADMIN in user_roles:
        return True
    
    # Check role-based permissions from constants
    for role in user_roles:
        role_permissions = ROLE_PERMISSIONS.get(role, [])
        if required_permission in role_permissions:
            return True
    
    return False


def require_roles(required_roles: List[str]):
    """
    Decorator to require specific roles for function access.
    
    Args:
        required_roles: List of required role names
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            # This would typically get user roles from JWT token or session
            # For now, this is a placeholder
            user_roles = kwargs.get('user_roles', [])
            
            if not any(role in user_roles for role in required_roles):
                raise InsufficientPermissionsError(
                    f"One of these roles required: {', '.join(required_roles)}"
                )
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


# Global RBAC manager instance
rbac_manager_instance = RBACManager()

__all__ = [
    'has_permission',
    'require_roles', 
    'rbac_manager_instance'
]
