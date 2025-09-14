"""
Action enumeration for RBAC system.
"""

from enum import Enum


class Action(Enum):
    """Enumeration of actions that can be performed on resources."""
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    LIST = "list"
    MANAGE = "manage"
    EXECUTE = "execute"
