"""
Permission class for RBAC system.
"""

from dataclasses import dataclass
from typing import Dict, Any, Optional, Union

from auth.rbac.resource_type import ResourceType
from auth.rbac.action import Action


@dataclass
class Permission:
    """Represents a specific permission."""

    resource: Union[ResourceType, str]
    action: Union[Action, str]
    conditions: Optional[Dict[str, Any]] = None

    def __str__(self) -> str:
        resource = (
            self.resource.value
            if isinstance(self.resource, ResourceType)
            else self.resource
        )
        action = self.action.value if isinstance(self.action, Action) else self.action
        return f"{resource}:{action}"

    def matches(
        self, resource: Union[ResourceType, str], action: Union[Action, str]
    ) -> bool:
        """Check if this permission matches the given resource and action."""
        resource_str = (
            resource.value if isinstance(resource, ResourceType) else resource
        )
        action_str = action.value if isinstance(action, Action) else action

        perm_resource = (
            self.resource.value
            if isinstance(self.resource, ResourceType)
            else self.resource
        )
        perm_action = (
            self.action.value if isinstance(self.action, Action) else self.action
        )

        return perm_resource == resource_str and perm_action == action_str
