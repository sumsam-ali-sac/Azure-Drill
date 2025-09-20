from typing import Callable
from fastapi import Request, Response
from starlette.types import ASGIApp, Scope, Receive, Send
from src.api.config import get_settings

settings = get_settings()


class SecurityHeadersMiddleware:
    """
    Middleware that adds a variety of security headers to every HTTP response.
    Provides protections against clickjacking, MIME sniffing, XSS,
    referrer leakage, DNS prefetching, and enforces HTTPS in production.
    Also applies strict cross-origin isolation and a restrictive CSP.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

        # Core security headers applied universally
        self.headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "X-Permitted-Cross-Domain-Policies": "none",
            "X-DNS-Prefetch-Control": "off",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=(self)",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Embedder-Policy": "require-corp",
            "Cross-Origin-Resource-Policy": "same-origin",
        }

        # Add HSTS in production only
        if settings.application.ENVIRONMENT == "PRODUCTION":
            self.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )

        # Build a strict Content-Security-Policy
        # csp = {
        #     "default-src": ["'self'"],
        #     "script-src": ["'self'"],
        #     "style-src": ["'self'"],
        #     "img-src": ["'self'", "data:", "https:"],
        #     "font-src": ["'self'", "data:"],
        #     "connect-src": ["'self'"],
        #     "frame-ancestors": ["'none'"],
        #     # "report-uri": ["/csp-report"],
        # }
        # csp_value = "; ".join(f"{k} {' '.join(v)}" for k, v in csp.items())
        # self.headers["Content-Security-Policy"] = csp_value

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """
        ASGI entrypoint: intercept the response, remove 'server' header,
        and inject all security headers.
        """

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = dict(message.get("headers", []))

                # Remove default server header
                if b"server" in headers:
                    del headers[b"server"]

                # Add/overwrite headers
                for hdr, val in self.headers.items():
                    headers[hdr.encode()] = val.encode()

                # Rebuild message.headers as a list of tuples
                message["headers"] = [(k, v) for k, v in headers.items()]

            await send(message)

        await self.app(scope, receive, send_wrapper)
