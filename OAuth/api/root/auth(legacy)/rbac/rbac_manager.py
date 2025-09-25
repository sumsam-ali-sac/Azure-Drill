"""
RBAC Manager for role and permission management.
"""

from typing import Dict, List, Set, Optional, Union

from root.authrbac.resource_type import ResourceType
from root.authrbac.action import Action
from root.authrbac.permission import Permission
from root.authrbac.role import Role
from root.authcommon.constants import (
    ROLE_USER,
    ROLE_ADMIN,
    ROLE_MODERATOR,
    ROLE_PERMISSIONS,
)
from root.authcommon.exceptions import InsufficientPermissionsError


class RBACManager:
    """Manages roles, permissions, and authorization logic."""

    def __init__(self):
        self.roles: Dict[str, Role] = {}
        self.user_roles: Dict[str, Set[str]] = {}  # Use database in production
        self._initialize_default_roles()

    def _initialize_default_roles(self):
        """Initialize default system roles."""
        # User role - basic permissions
        user_permissions = [
            Permission(ResourceType.USER, Action.READ),
            Permission(ResourceType.USER, Action.UPDATE),  # Own profile only
            Permission(ResourceType.POST, Action.CREATE),
            Permission(ResourceType.POST, Action.READ),
            Permission(ResourceType.COMMENT, Action.CREATE),
            Permission(ResourceType.COMMENT, Action.READ),
            Permission(ResourceType.FILE, Action.CREATE),
            Permission(ResourceType.FILE, Action.READ),
        ]

        self.roles[ROLE_USER] = Role(
            name=ROLE_USER,
            description="Standard user with basic permissions",
            permissions=user_permissions,
            is_system_role=True,
        )

        # Moderator role - content management permissions
        moderator_permissions = user_permissions + [
            Permission(ResourceType.POST, Action.UPDATE),
            Permission(ResourceType.POST, Action.DELETE),
            Permission(ResourceType.COMMENT, Action.UPDATE),
            Permission(ResourceType.COMMENT, Action.DELETE),
            Permission(ResourceType.USER, Action.LIST),
        ]

        self.roles[ROLE_MODERATOR] = Role(
            name=ROLE_MODERATOR,
            description="Moderator with content management permissions",
            permissions=moderator_permissions,
            inherits_from=[ROLE_USER],
            is_system_role=True,
        )

        # Admin role - full system permissions
        admin_permissions = moderator_permissions + [
            Permission(ResourceType.USER, Action.CREATE),
            Permission(ResourceType.USER, Action.DELETE),
            Permission(ResourceType.USER, Action.MANAGE),
            Permission(ResourceType.ADMIN_PANEL, Action.READ),
            Permission(ResourceType.ADMIN_PANEL, Action.MANAGE),
            Permission(ResourceType.SYSTEM, Action.MANAGE),
            Permission(ResourceType.API, Action.EXECUTE),
        ]

        self.roles[ROLE_ADMIN] = Role(
            name=ROLE_ADMIN,
            description="Administrator with full system access",
            permissions=admin_permissions,
            inherits_from=[ROLE_MODERATOR],
            is_system_role=True,
        )

    def user_has_permission(
        self,
        user_id: str,
        resource: Union[ResourceType, str],
        action: Union[Action, str],
        resource_owner_id: Optional[str] = None,
    ) -> bool:
        """
        Check if user has specific permission.

        Args:
            user_id: User identifier
            resource: Resource type
            action: Action to perform
            resource_owner_id: Owner of the resource (for ownership checks)

        Returns:
            True if user has permission
        """
        # Check for ownership-based permissions
        if resource_owner_id and user_id == resource_owner_id:
            # Users can always read/update their own resources
            if action in [Action.READ, Action.UPDATE]:
                return True

        # Check role-based permissions
        user_permissions = self.get_user_permissions(user_id)

        for permission in user_permissions:
            if permission.matches(resource, action):
                # Check additional conditions if any
                if permission.conditions:
                    # TODO: Implement condition checking logic
                    pass
                return True

        return False

    def get_user_permissions(self, user_id: str) -> List[Permission]:
        """Get all permissions for user (including inherited)."""
        permissions = []
        processed_roles = set()

        def collect_permissions(role_names: List[str]):
            for role_name in role_names:
                if role_name in processed_roles or role_name not in self.roles:
                    continue

                processed_roles.add(role_name)
                role = self.roles[role_name]
                permissions.extend(role.permissions)

                # Recursively collect from parent roles
                if role.inherits_from:
                    collect_permissions(role.inherits_from)

        user_role_names = self.get_user_roles(user_id)
        collect_permissions(user_role_names)

        # Remove duplicates while preserving order
        seen = set()
        unique_permissions = []
        for perm in permissions:
            perm_str = str(perm)
            if perm_str not in seen:
                seen.add(perm_str)
                unique_permissions.append(perm)

        return unique_permissions

    def get_user_roles(self, user_id: str) -> List[str]:
        """Get all roles assigned to user."""
        return list(self.user_roles.get(user_id, set()))
