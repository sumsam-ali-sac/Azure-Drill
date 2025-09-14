"""
Common package initialization
"""

from src.api.common.telemetry.tracing import trace_operation

__version__ = "1.0.0"
__all__ = [
    "trace_operation"
]
