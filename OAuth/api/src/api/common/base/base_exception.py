
from typing import Optional, Dict, Any
from fastapi import HTTPException, status


class BaseHTTPException(HTTPException):
    """Base exception class for chat application with HTTP status codes"""

    def __init__(
        self,
        message: str,
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None
    ):
        self.message = message
        self.error_code = error_code
        self.details = details or {}

        # Create detail dict for FastAPI
        detail = {
            "message": message,
            "error_code": error_code,
            "details": self.details
        }

        super().__init__(
            status_code=status_code,
            detail=detail,
            headers=headers
        )
