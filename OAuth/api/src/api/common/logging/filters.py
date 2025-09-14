import logging

try:
    from opentelemetry.trace import get_current_span

    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False


class TraceContextFilter(logging.Filter):
    """Attach trace_id and span_id from OpenTelemetry to log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        if OTEL_AVAILABLE:
            try:
                span = get_current_span()
                ctx = span.get_span_context()
                record.trace_id = format(ctx.trace_id, "032x") if ctx else "none"
                record.span_id = format(ctx.span_id, "016x") if ctx else "none"
            except Exception:
                record.trace_id = record.span_id = "none"
        else:
            record.trace_id = record.span_id = "none"
        return True
