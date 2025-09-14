"""
Resource type enumeration for RBAC system.
"""

from enum import Enum


class ResourceType(Enum):
    """Enumeration of resource types for permission checking."""
    USER = "user"
    POST = "post"
    COMMENT = "comment"
    ADMIN_PANEL = "admin_panel"
    SYSTEM = "system"
    FILE = "file"
    API = "api"
