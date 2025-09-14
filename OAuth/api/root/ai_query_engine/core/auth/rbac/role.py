"""
Role class for RBAC system.
"""

from dataclasses import dataclass
from typing import List, Optional, Union

from auth.rbac.permission import Permission
from auth.rbac.resource_type import ResourceType
from auth.rbac.action import Action


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
