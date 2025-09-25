"""RBAC (Role-Based Access Control) module."""

from root.authrbac.resource_type import ResourceType
from root.authrbac.action import Action
from root.authrbac.permission import Permission
from root.authrbac.role import Role
from root.authrbac.rbac_manager import RBACManager

__all__ = ["ResourceType", "Action", "Permission", "Role", "RBACManager"]
