"""
Role-Based Access Control (RBAC) utilities.
Provides comprehensive authorization and permission management.
"""

from typing import Dict, List, Set, Optional, Any, Union
from enum import Enum
from dataclasses import dataclass
from .constants import (
    ROLE_USER,
    ROLE_ADMIN,
    ROLE_MODERATOR,
    PERMISSION_READ,
    PERMISSION_WRITE,
    PERMISSION_DELETE,
    PERMISSION_ADMIN,
    ROLE_PERMISSIONS
)
from .exceptions import InsufficientPermissionsError


class ResourceType(Enum):
    """Enumeration of resource types for permission checking."""
    USER = "user"
    POST = "post"
    COMMENT = "comment"
    ADMIN_PANEL = "admin_panel"
    SYSTEM = "system"
    FILE = "file"
    API = "api"


class Action(Enum):
    """Enumeration of actions that can be performed on resources."""
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    LIST = "list"
    MANAGE = "manage"
    EXECUTE = "execute"


@dataclass
class Permission:
    """Represents a specific permission."""
    resource: Union[ResourceType, str]
    action: Union[Action, str]
    conditions: Optional[Dict[str, Any]] = None
    
    def __str__(self) -> str:
        resource = self.resource.value if isinstance(self.resource, ResourceType) else self.resource
        action = self.action.value if isinstance(self.action, Action) else self.action
        return f"{resource}:{action}"
    
    def matches(self, resource: Union[ResourceType, str], action: Union[Action, str]) -> bool:
        """Check if this permission matches the given resource and action."""
        resource_str = resource.value if isinstance(resource, ResourceType) else resource
        action_str = action.value if isinstance(action, Action) else action
        
        perm_resource = self.resource.value if isinstance(self.resource, ResourceType) else self.resource
        perm_action = self.action.value if isinstance(self.action, Action) else self.action
        
        return perm_resource == resource_str and perm_action == action_str


@dataclass
class Role:
    """Represents a role with associated permissions."""
    name: str
    description: str
    permissions: List[Permission]
    inherits_from: Optional[List[str]] = None
    is_system_role: bool = False
    
    def has_permission(self, resource: Union[ResourceType, str], action: Union[Action, str]) -> bool:
        """Check if this role has a specific permission."""
        return any(perm.matches(resource, action) for perm in self.permissions)
    
    def get_permission_strings(self) -> List[str]:
        """Get list of permission strings for this role."""
        return [str(perm) for perm in self.permissions]


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
            is_system_role=True
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
            is_system_role=True
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
            is_system_role=True
        )
    
    def create_role(
        self,
        name: str,
        description: str,
        permissions: List[Permission],
        inherits_from: Optional[List[str]] = None
    ) -> Role:
        """
        Create a new custom role.
        
        Args:
            name: Role name
            description: Role description
            permissions: List of permissions
            inherits_from: List of parent roles to inherit from
        
        Returns:
            Created role
        """
        if name in self.roles:
            raise ValueError(f"Role '{name}' already exists")
        
        # Validate parent roles exist
        if inherits_from:
            for parent_role in inherits_from:
                if parent_role not in self.roles:
                    raise ValueError(f"Parent role '{parent_role}' does not exist")
        
        role = Role(
            name=name,
            description=description,
            permissions=permissions,
            inherits_from=inherits_from,
            is_system_role=False
        )
        
        self.roles[name] = role
        return role
    
    def delete_role(self, name: str) -> bool:
        """
        Delete a custom role.
        
        Args:
            name: Role name to delete
        
        Returns:
            True if role was deleted
        """
        if name not in self.roles:
            return False
        
        role = self.roles[name]
        if role.is_system_role:
            raise ValueError("Cannot delete system roles")
        
        # Remove role from all users
        for user_id in list(self.user_roles.keys()):
            self.user_roles[user_id].discard(name)
        
        del self.roles[name]
        return True
    
    def get_role(self, name: str) -> Optional[Role]:
        """Get role by name."""
        return self.roles.get(name)
    
    def list_roles(self, include_system: bool = True) -> List[Role]:
        """
        List all roles.
        
        Args:
            include_system: Whether to include system roles
        
        Returns:
            List of roles
        """
        if include_system:
            return list(self.roles.values())
        else:
            return [role for role in self.roles.values() if not role.is_system_role]
    
    def assign_role_to_user(self, user_id: str, role_name: str) -> bool:
        """
        Assign role to user.
        
        Args:
            user_id: User identifier
            role_name: Role name to assign
        
        Returns:
            True if role was assigned
        """
        if role_name not in self.roles:
            raise ValueError(f"Role '{role_name}' does not exist")
        
        if user_id not in self.user_roles:
            self.user_roles[user_id] = set()
        
        self.user_roles[user_id].add(role_name)
        return True
    
    def remove_role_from_user(self, user_id: str, role_name: str) -> bool:
        """
        Remove role from user.
        
        Args:
            user_id: User identifier
            role_name: Role name to remove
        
        Returns:
            True if role was removed
        """
        if user_id not in self.user_roles:
            return False
        
        self.user_roles[user_id].discard(role_name)
        return True
    
    def get_user_roles(self, user_id: str) -> List[str]:
        """
        Get all roles assigned to user.
        
        Args:
            user_id: User identifier
        
        Returns:
            List of role names
        """
        return list(self.user_roles.get(user_id, set()))
    
    def get_user_permissions(self, user_id: str) -> List[Permission]:
        """
        Get all permissions for user (including inherited).
        
        Args:
            user_id: User identifier
        
        Returns:
            List of permissions
        """
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
    
    def user_has_permission(
        self,
        user_id: str,
        resource: Union[ResourceType, str],
        action: Union[Action, str],
        resource_owner_id: Optional[str] = None
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
    
    def user_has_role(self, user_id: str, role_name: str) -> bool:
        """
        Check if user has specific role.
        
        Args:
            user_id: User identifier
            role_name: Role name to check
        
        Returns:
            True if user has role
        """
        user_roles = self.user_roles.get(user_id, set())
        
        # Direct role check
        if role_name in user_roles:
            return True
        
        # Check inherited roles
        for user_role_name in user_roles:
            if user_role_name in self.roles:
                role = self.roles[user_role_name]
                if role.inherits_from and role_name in role.inherits_from:
                    return True
        
        return False
    
    def require_permission(
        self,
        user_id: str,
        resource: Union[ResourceType, str],
        action: Union[Action, str],
        resource_owner_id: Optional[str] = None
    ):
        """
        Require user to have specific permission (raises exception if not).
        
        Args:
            user_id: User identifier
            resource: Resource type
            action: Action to perform
            resource_owner_id: Owner of the resource
        
        Raises:
            InsufficientPermissionsError: If user lacks permission
        """
        if not self.user_has_permission(user_id, resource, action, resource_owner_id):
            resource_str = resource.value if isinstance(resource, ResourceType) else resource
            action_str = action.value if isinstance(action, Action) else action
            raise InsufficientPermissionsError(
                f"Permission denied: {resource_str}:{action_str}"
            )
    
    def require_role(self, user_id: str, role_name: str):
        """
        Require user to have specific role (raises exception if not).
        
        Args:
            user_id: User identifier
            role_name: Required role name
        
        Raises:
            InsufficientPermissionsError: If user lacks role
        """
        if not self.user_has_role(user_id, role_name):
            raise InsufficientPermissionsError(f"Role required: {role_name}")
    
    def get_accessible_resources(
        self,
        user_id: str,
        resource_type: Union[ResourceType, str],
        action: Union[Action, str]
    ) -> List[str]:
        """
        Get list of resources user can access with given action.
        
        Args:
            user_id: User identifier
            resource_type: Type of resource
            action: Action to perform
        
        Returns:
            List of accessible resource IDs
        """
        # This is a placeholder implementation
        # In a real system, you would query your database for resources
        # and filter based on permissions
        
        if self.user_has_permission(user_id, resource_type, action):
            # User has global permission for this resource type
            return ["*"]  # Represents all resources
        
        # TODO: Implement resource-specific permission checking
        return []
    
    def create_permission_matrix(self) -> Dict[str, Dict[str, List[str]]]:
        """
        Create a permission matrix showing all roles and their permissions.
        
        Returns:
            Dictionary mapping roles to resources and their allowed actions
        """
        matrix = {}
        
        for role_name, role in self.roles.items():
            matrix[role_name] = {}
            
            for permission in role.permissions:
                resource = permission.resource.value if isinstance(permission.resource, ResourceType) else permission.resource
                action = permission.action.value if isinstance(permission.action, Action) else permission.action
                
                if resource not in matrix[role_name]:
                    matrix[role_name][resource] = []
                
                matrix[role_name][resource].append(action)
        
        return matrix
    
    def validate_role_hierarchy(self) -> List[str]:
        """
        Validate role hierarchy for circular dependencies.
        
        Returns:
            List of validation errors
        """
        errors = []
        
        def check_circular_dependency(role_name: str, visited: Set[str], path: List[str]) -> bool:
            if role_name in visited:
                cycle_start = path.index(role_name)
                cycle = " -> ".join(path[cycle_start:] + [role_name])
                errors.append(f"Circular dependency detected: {cycle}")
                return True
            
            if role_name not in self.roles:
                errors.append(f"Role '{role_name}' referenced but not defined")
                return False
            
            role = self.roles[role_name]
            if not role.inherits_from:
                return False
            
            visited.add(role_name)
            path.append(role_name)
            
            for parent_role in role.inherits_from:
                if check_circular_dependency(parent_role, visited.copy(), path.copy()):
                    return True
            
            return False
        
        for role_name in self.roles:
            check_circular_dependency(role_name, set(), [])
        
        return errors


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
