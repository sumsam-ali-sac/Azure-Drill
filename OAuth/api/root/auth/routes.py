"""
FastAPI routes for authentication endpoints.
Provides complete REST API for all authentication operations.
"""

from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, Request, Response, HTTPException, status
from fastapi.responses import JSONResponse, RedirectResponse
from .core import auth_manager
from .middleware import (
    get_current_user,
    get_current_user_optional,
    require_roles,
    create_auth_response,
    create_error_response,
    AuthUser
)
from .schemas import (
    UserRegistration,
    UserLogin,
    TokenRefresh,
    OTPRequest,
    OTPVerification,
    PasswordResetRequest,
    PasswordReset,
    PasswordChange,
    SocialLoginRequest,
    APIResponse,
    HealthCheck
)
from .session_utils import token_cookie_manager
from .exceptions import *
from .constants import SUCCESS_LOGOUT
from datetime import datetime


# Create router
auth_router = APIRouter(prefix="/auth", tags=["Authentication"])


@auth_router.post("/register", response_model=APIResponse)
async def register(
    registration_data: UserRegistration,
    response: Response
) -> Dict[str, Any]:
    """
    Register a new user account.
    
    Args:
        registration_data: User registration information
        response: FastAPI response object
    
    Returns:
        Registration result
    """
    try:
        result = auth_manager.register_user(registration_data)
        
        return {
            "success": True,
            "message": result["message"],
            "data": {
                "user": result["user"].dict(),
                "requires_verification": result["requires_verification"]
            }
        }
        
    except (EmailAlreadyExistsError, WeakPasswordError, RateLimitExceededError) as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)


@auth_router.post("/login", response_model=APIResponse)
async def login(
    login_data: UserLogin,
    request: Request,
    response: Response
) -> Dict[str, Any]:
    """
    Authenticate user with email and password.
    
    Args:
        login_data: Login credentials
        request: FastAPI request object
        response: FastAPI response object
    
    Returns:
        Authentication result with tokens
    """
    try:
        result = auth_manager.login_with_password(login_data, request)
        
        if result.get("requires_otp"):
            return {
                "success": False,
                "message": result["message"],
                "data": {
                    "requires_otp": True,
                    "otp_status": result["otp_status"]
                }
            }
        
        tokens = result["tokens"]
        user_data = result["user"].dict()
        
        return create_auth_response(
            tokens.access_token,
            tokens.refresh_token,
            user_data,
            response,
            result["message"]
        )
        
    except (InvalidCredentialsError, OTPInvalidError, RateLimitExceededError) as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)


@auth_router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    current_user: Optional[AuthUser] = Depends(get_current_user_optional)
) -> Dict[str, Any]:
    """
    Logout current user and clear session.
    
    Args:
        request: FastAPI request object
        response: FastAPI response object
        current_user: Current authenticated user (optional)
    
    Returns:
        Logout result
    """
    result = auth_manager.logout_user(request, response)
    return result


@auth_router.post("/refresh", response_model=APIResponse)
async def refresh_token(
    token_data: TokenRefresh,
    response: Response
) -> Dict[str, Any]:
    """
    Refresh access token using refresh token.
    
    Args:
        token_data: Refresh token data
        response: FastAPI response object
    
    Returns:
        New access token
    """
    try:
        result = auth_manager.refresh_token(token_data.refresh_token)
        return result
        
    except (TokenExpiredError, TokenInvalidError) as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)


@auth_router.post("/otp/send", response_model=APIResponse)
async def send_otp(otp_request: OTPRequest) -> Dict[str, Any]:
    """
    Send OTP code to user's email.
    
    Args:
        otp_request: OTP request information
    
    Returns:
        OTP send result
    """
    try:
        result = auth_manager.send_otp_code(otp_request)
        return result
        
    except (UserNotFoundError, RateLimitExceededError, EmailSendError) as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)


@auth_router.post("/password/reset/request", response_model=APIResponse)
async def request_password_reset(reset_request: PasswordResetRequest) -> Dict[str, Any]:
    """
    Request password reset for user.
    
    Args:
        reset_request: Password reset request
    
    Returns:
        Reset request result
    """
    try:
        result = auth_manager.request_password_reset(reset_request)
        return result
        
    except RateLimitExceededError as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)


@auth_router.post("/password/reset", response_model=APIResponse)
async def reset_password(reset_data: PasswordReset) -> Dict[str, Any]:
    """
    Reset user password using reset token.
    
    Args:
        reset_data: Password reset data
    
    Returns:
        Reset result
    """
    try:
        result = auth_manager.reset_password(reset_data)
        return result
        
    except (TokenInvalidError, TokenExpiredError, UserNotFoundError, WeakPasswordError) as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)


@auth_router.post("/password/change", response_model=APIResponse)
async def change_password(
    password_data: PasswordChange,
    current_user: AuthUser = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Change user password (authenticated operation).
    
    Args:
        password_data: Password change data
        current_user: Current authenticated user
    
    Returns:
        Password change result
    """
    try:
        result = auth_manager.change_user_password(
            current_user.email,
            password_data.current_password,
            password_data.new_password
        )
        return result
        
    except (InvalidCredentialsError, WeakPasswordError) as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)


@auth_router.get("/me")
async def get_current_user_profile(
    current_user: AuthUser = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Get current user's profile information.
    
    Args:
        current_user: Current authenticated user
    
    Returns:
        User profile data
    """
    return {
        "success": True,
        "data": {
            "user": current_user.to_dict()
        }
    }


@auth_router.get("/status")
async def get_auth_status(
    current_user: Optional[AuthUser] = Depends(get_current_user_optional)
) -> Dict[str, Any]:
    """
    Get authentication status.
    
    Args:
        current_user: Current user (optional)
    
    Returns:
        Authentication status
    """
    if current_user:
        return {
            "success": True,
            "data": {
                "is_authenticated": True,
                "user": current_user.to_dict()
            }
        }
    else:
        return {
            "success": True,
            "data": {
                "is_authenticated": False
            }
        }


# OAuth Routes

@auth_router.post("/oauth/{provider}/authorize")
async def oauth_authorize(
    provider: str,
    social_request: SocialLoginRequest,
    request: Request
) -> Dict[str, Any]:
    """
    Get OAuth authorization URL for social login.
    
    Args:
        provider: OAuth provider name
        social_request: Social login request
        request: FastAPI request object
    
    Returns:
        Authorization URL and state
    """
    try:
        social_request.provider = provider
        result = auth_manager.get_oauth_authorization_url(social_request, request)
        return result
        
    except OAuthError as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)


@auth_router.get("/oauth/{provider}/callback")
async def oauth_callback(
    provider: str,
    code: str,
    state: str,
    request: Request,
    response: Response
) -> RedirectResponse:
    """
    Handle OAuth callback and authenticate user.
    
    Args:
        provider: OAuth provider name
        code: Authorization code
        state: State parameter
        request: FastAPI request object
        response: FastAPI response object
    
    Returns:
        Redirect response to frontend
    """
    try:
        result = await auth_manager.handle_oauth_callback(provider, code, state, request)
        
        tokens = result["tokens"]
        user_data = result["user"].dict()
        
        # Set auth cookies
        token_cookie_manager.set_auth_cookies(
            response,
            tokens.access_token,
            tokens.refresh_token,
            user_data
        )
        
        # Redirect to frontend with success
        redirect_url = f"{auth_manager.config.FRONTEND_URL}/auth/success"
        return RedirectResponse(url=redirect_url)
        
    except OAuthError as e:
        # Redirect to frontend with error
        error_url = f"{auth_manager.config.FRONTEND_URL}/auth/error?message={e.detail}"
        return RedirectResponse(url=error_url)


# Admin Routes

@auth_router.get("/admin/users")
async def list_users(
    current_user: AuthUser = Depends(require_roles(["admin"]))
) -> Dict[str, Any]:
    """
    List all users (admin only).
    
    Args:
        current_user: Current authenticated admin user
    
    Returns:
        List of users
    """
    # This would typically query your database
    # For now, return placeholder data
    return {
        "success": True,
        "data": {
            "users": [],
            "total": 0
        }
    }


@auth_router.post("/admin/users/{user_id}/roles")
async def assign_user_roles(
    user_id: str,
    roles: Dict[str, list],
    current_user: AuthUser = Depends(require_roles(["admin"]))
) -> Dict[str, Any]:
    """
    Assign roles to user (admin only).
    
    Args:
        user_id: User ID to assign roles to
        roles: Dictionary with roles list
        current_user: Current authenticated admin user
    
    Returns:
        Role assignment result
    """
    # This would typically update your database
    # For now, return placeholder response
    return {
        "success": True,
        "message": "Roles assigned successfully"
    }


# Health Check

@auth_router.get("/health", response_model=HealthCheck)
async def health_check() -> HealthCheck:
    """
    Health check endpoint.
    
    Returns:
        Service health status
    """
    return HealthCheck(
        status="healthy",
        version="1.0.0",
        timestamp=datetime.utcnow(),
        dependencies={
            "database": "connected",
            "redis": "connected",
            "email": "configured" if auth_manager.email_manager.smtp_configured else "not_configured"
        }
    )


# Error handlers (to be registered with FastAPI app)
def register_auth_exception_handlers(app):
    """Register authentication exception handlers with FastAPI app."""
    
    @app.exception_handler(InvalidCredentialsError)
    async def invalid_credentials_handler(request: Request, exc: InvalidCredentialsError):
        return create_error_response(exc, exc.status_code)
    
    @app.exception_handler(TokenExpiredError)
    async def token_expired_handler(request: Request, exc: TokenExpiredError):
        return create_error_response(exc, exc.status_code)
    
    @app.exception_handler(TokenInvalidError)
    async def token_invalid_handler(request: Request, exc: TokenInvalidError):
        return create_error_response(exc, exc.status_code)
    
    @app.exception_handler(InsufficientPermissionsError)
    async def insufficient_permissions_handler(request: Request, exc: InsufficientPermissionsError):
        return create_error_response(exc, exc.status_code)
    
    @app.exception_handler(RateLimitExceededError)
    async def rate_limit_handler(request: Request, exc: RateLimitExceededError):
        return create_error_response(exc, exc.status_code)
    
    @app.exception_handler(OAuthError)
    async def oauth_error_handler(request: Request, exc: OAuthError):
        return create_error_response(exc, exc.status_code)
