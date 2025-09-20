"""
Error handling middleware for API endpoints.
"""

from typing import Union
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from auth_service.exceptions.auth_exceptions import AuthServiceError

async def auth_service_error_handler(request: Request, exc: AuthServiceError) -> JSONResponse:
    """
    Handle AuthServiceError exceptions.
    
    Args:
        request: FastAPI request object
        exc: AuthServiceError exception
        
    Returns:
        JSON error response
    """
    status_code = 400
    
    # Map specific error types to HTTP status codes
    error_type = exc.error_type
    if error_type in ["INVALID_CREDENTIALS", "TOKEN_EXPIRED", "TOKEN_INVALID"]:
        status_code = 401
    elif error_type in ["USER_NOT_FOUND", "TOKEN_NOT_FOUND"]:
        status_code = 404
    elif error_type in ["USER_ALREADY_EXISTS", "EMAIL_ALREADY_EXISTS"]:
        status_code = 409
    elif error_type in ["INVALID_INPUT", "VALIDATION_ERROR"]:
        status_code = 422
    
    return JSONResponse(
        status_code=status_code,
        content={
            "success": False,
            "message": exc.message,
            "error_code": exc.error_type,
            "details": exc.details
        }
    )

async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """
    Handle Pydantic validation errors.
    
    Args:
        request: FastAPI request object
        exc: RequestValidationError exception
        
    Returns:
        JSON error response
    """
    return JSONResponse(
        status_code=422,
        content={
            "success": False,
            "message": "Validation error",
            "error_code": "VALIDATION_ERROR",
            "details": exc.errors()
        }
    )

async def http_exception_handler(request: Request, exc: Union[HTTPException, StarletteHTTPException]) -> JSONResponse:
    """
    Handle HTTP exceptions.
    
    Args:
        request: FastAPI request object
        exc: HTTP exception
        
    Returns:
        JSON error response
    """
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "message": exc.detail,
            "error_code": f"HTTP_{exc.status_code}"
        }
    )

async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Handle general exceptions.
    
    Args:
        request: FastAPI request object
        exc: General exception
        
    Returns:
        JSON error response
    """
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "message": "Internal server error",
            "error_code": "INTERNAL_ERROR",
            "details": str(exc) if request.app.debug else None
        }
    )
