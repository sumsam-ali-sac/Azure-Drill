from abc import ABC, abstractmethod
from typing import Any


class BaseTracer(ABC):
    """Abstract base class for tracers."""

    @abstractmethod
    def start_as_current_span(self, name: str, **kwargs: Any):
        """Start a span and return a context manager."""
        pass
