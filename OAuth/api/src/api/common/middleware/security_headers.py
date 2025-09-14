from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from src.api.config import settings


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware that adds a variety of security headers to every HTTP response.
    Headers include protections against clickjacking, MIME sniffing, cross-site scripting,
    referrer leakage, DNS prefetching, and enforce HTTPS via HSTS in production.
    Also provides strict cross-origin isolation and feature controls.
    """

    def __init__(self, app):
        super().__init__(app)
        # Core security headers applied universally
        self.headers = {
            "X-Content-Type-Options": "nosniff",  # Prevent MIME-type sniffing
            "X-Frame-Options": "DENY",            # Disallow framing to prevent clickjacking
            "Referrer-Policy": "strict-origin-when-cross-origin",  # Limit referer info
            # Disable Flash cross-domain policies
            "X-Permitted-Cross-Domain-Policies": "none",
            "X-DNS-Prefetch-Control": "off",      # Disable DNS prefetch for privacy
            # Opt out of powerful features
            "Permissions-Policy": "camera=(), microphone=(), geolocation=(self)",
            "Cross-Origin-Opener-Policy": "same-origin",  # Cross-origin isolation
            "Cross-Origin-Embedder-Policy": "require-corp",  # Cross-origin isolation
            "Cross-Origin-Resource-Policy": "same-origin",  # Cross-origin isolation
        }
        # Add HSTS only in production to enforce HTTPS
        if settings.is_production:  # Use the top-level property
            self.headers["Strict-Transport-Security"] = (
                # Tells browsers to only use HTTPS for one year
                "max-age=31536000; includeSubDomains; preload"
            )
        # Build a strict Content-Security-Policy
        # - default-src 'self': only load resources from own origin
        # - script-src/style-src without 'unsafe-inline' in prod; use nonces/hashes instead
        # - report-uri: send violation reports to /csp-report endpoint
        csp = {
            "default-src": ["'self'"],
            "script-src": ["'self'"],
            "style-src": ["'self'"],
            "img-src": ["'self'", "data:", "https:"],
            "font-src": ["'self'", "data:"],
            "connect-src": ["'self'"],
            "frame-ancestors": ["'none'"],  # Prevent embedding entirely
            # Endpoint to collect CSP violation reports
            "report-uri": ["/csp-report"],
        }
        csp_value = "; ".join(f"{k} {' '.join(v)}" for k, v in csp.items())
        self.headers["Content-Security-Policy"] = csp_value

    async def dispatch(self, request: Request, call_next) -> Response:
        """
        Intercept each request/response cycle.
        - If it's a CSP violation report, return 204 immediately.
        - Otherwise, call downstream handlers, then append all security headers.
        - Strip default 'server' header leaked by frameworks.
        """
        # Handle CSP violation reports
        if request.url.path == "/csp-report" and request.method == "POST":
            # TODO: parse JSON payload and log or forward to monitoring
            return Response(status_code=204)

        # Process normal request and get response
        response = await call_next(request)

        # Remove any default server header for obscurity
        response.headers.pop("server", None)

        # Append each security header defined in __init__
        for hdr, val in self.headers.items():
            response.headers[hdr] = val

        return response
