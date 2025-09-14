from contextlib import contextmanager
from typing import Any, Dict, Optional
from src.api.common.logging import get_tracer


@contextmanager
def trace_operation(
    operation_name: str, attributes: Optional[Dict[str, Any]] = None
) -> Any:
    """
    Context manager for tracing operations with OpenTelemetry.
    Creates a new span for the given operation.

    Args:
        operation_name (str): The name of the operation to trace.
        attributes (Optional[Dict[str, Any]]): Optional dictionary of attributes
                                                to add to the span.

    Yields:
        opentelemetry.trace.Span: The created OpenTelemetry span.
                                  This will be a NoOpSpan if tracing is disabled.
    """
    tracer = get_tracer()
    with tracer.start_as_current_span(operation_name) as span:
        if attributes:
            span.set_attributes(attributes)
        yield span
