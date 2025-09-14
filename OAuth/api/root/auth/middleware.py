"""
FastAPI middleware and dependency injection for authentication and authorization.
Provides decorators, dependencies, and middleware for seamless integration.
"""

import jwt
from typing import Optional, List, Dict, Any, Callable, Union
from functools import wraps
from fastapi import Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from .configs import config
from .core import auth_manager
from .token_utils import token_manager
from .rbac_utils import rbac_manager_instance, ResourceType, Action
from .session_utils import token_cookie_manager
from .exceptions import (
    TokenExpiredError,
    TokenInvalidError,
    InsufficientPermissionsError,
    RateLimitExceededError
)
from .constants import TOKEN_TYPE_ACCESS


# Security scheme for FastAPI
security = HTTPBearer(auto_error=False)


class AuthUser:
    """Represents an authenticated user with their permissions."""
    
    def __init__(self, payload: Dict[str, Any]):
        self.payload = payload
        self.user_id = payload.get('user_id')
        self.email = payload.get('email')
        self.sub = payload.get('sub')
        self.roles = payload.get('roles', [])
        self.first_name = payload.get('first_name')
        self.last_name = payload.get('last_name')
        self.is_verified = payload.get('is_verified', False)
    
    @property
    def is_admin(self) -> bool:
        """Check if user has admin role."""
        return 'admin' in self.roles
    
    @property
    def is_moderator(self) -> bool:
        """Check if user has moderator role."""
        return 'moderator' in self.roles or self.is_admin
    
    def has_role(self, role: str) -> bool:
        """Check if user has specific role."""
        return role in self.roles
    
    def has_permission(
        self,
        resource: Union[ResourceType, str],
        action: Union[Action, str],
        resource_owner_id: Optional[str] = None
    ) -> bool:
        """Check if user has specific permission."""
        return rbac_manager_instance.user_has_permission(
            self.user_id, resource, action, resource_owner_id
        )
    
    def require_permission(
        self,
        resource: Union[ResourceType, str],
        action: Union[Action, str],
        resource_owner_id: Optional[str] = None
    ):
        """Require specific permission (raises exception if not authorized)."""
        rbac_manager_instance.require_permission(
            self.user_id, resource, action, resource_owner_id
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'user_id': self.user_id,
            'email': self.email,
            'roles': self.roles,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'is_verified': self.is_verified,
            'is_admin': self.is_admin,
            'is_moderator': self.is_moderator
        }


async def get_current_user_optional(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Optional[AuthUser]:
    """
    Get current user from token (optional - doesn't raise exception if no token).
    
    Args:
        request: FastAPI request object
        credentials: HTTP authorization credentials
    
    Returns:
        AuthUser instance if authenticated, None otherwise
    """
    token = None
    
    # Try to get token from Authorization header
    if credentials:
        token = credentials.credentials
    
    # Try to get token from cookie as fallback
    if not token:
        cookies = token_cookie_manager.get_tokens_from_cookies(request)
        refresh_token = cookies.get('refresh_token')
        if refresh_token:
            try:
                # Try to refresh the access token
                refresh_result = auth_manager.refresh_token(refresh_token)
                token = refresh_result.get('access_token')
            except Exception:
                pass
    
    if not token:
        return None
    
    try:
        payload = token_manager.verify_token(token, token_type=TOKEN_TYPE_ACCESS)
        return AuthUser(payload)
    except (TokenExpiredError, TokenInvalidError):
        return None


async def get_current_user(
    current_user: Optional[AuthUser] = Depends(get_current_user_optional)
) -> AuthUser:
    """
    Get current authenticated user (required - raises exception if not authenticated).
    
    Args:
        current_user: Current user from optional dependency
    
    Returns:
        AuthUser instance
    
    Raises:
        HTTPException: If user is not authenticated
    """
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return current_user


async def get_admin_user(
    current_user: AuthUser = Depends(get_current_user)
) -> AuthUser:
    """
    Get current user and require admin role.
    
    Args:
        current_user: Current authenticated user
    
    Returns:
        AuthUser instance with admin role
    
    Raises:
        HTTPException: If user is not admin
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user


async def get_moderator_user(
    current_user: AuthUser = Depends(get_current_user)
) -> AuthUser:
    """
    Get current user and require moderator or admin role.
    
    Args:
        current_user: Current authenticated user
    
    Returns:
        AuthUser instance with moderator or admin role
    
    Raises:
        HTTPException: If user is not moderator or admin
    """
    if not current_user.is_moderator:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Moderator access required"
        )
    return current_user


def require_roles(required_roles: List[str]):
    """
    Dependency factory to require specific roles.
    
    Args:
        required_roles: List of required role names
    
    Returns:
        FastAPI dependency function
    """
    async def role_dependency(current_user: AuthUser = Depends(get_current_user)) -> AuthUser:
        if not any(current_user.has_role(role) for role in required_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"One of these roles required: {', '.join(required_roles)}"
            )
        return current_user
    
    return role_dependency


def require_permission(
    resource: Union[ResourceType, str],
    action: Union[Action, str]
):
    """
    Dependency factory to require specific permission.
    
    Args:
        resource: Resource type
        action: Action to perform
    
    Returns:
        FastAPI dependency function
    """
    async def permission_dependency(current_user: AuthUser = Depends(get_current_user)) -> AuthUser:
        try:
            current_user.require_permission(resource, action)
            return current_user
        except InsufficientPermissionsError as e:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=str(e.detail)
            )
    
    return permission_dependency


def auth_required(func: Callable = None, *, roles: Optional[List[str]] = None):
    """
    Decorator to require authentication and optionally specific roles.
    
    Args:
        func: Function to decorate
        roles: Optional list of required roles
    
    Returns:
        Decorated function
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        async def wrapper(*args, **kwargs):
            # Extract request from args/kwargs
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            
            if not request:
                request = kwargs.get('request')
            
            if not request:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Request object not found"
                )
            
            # Get current user
            current_user = await get_current_user_optional(request)
            if not current_user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )
            
            # Check roles if specified
            if roles and not any(current_user.has_role(role) for role in roles):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"One of these roles required: {', '.join(roles)}"
                )
            
            # Add current_user to kwargs
            kwargs['current_user'] = current_user
            
            return await f(*args, **kwargs)
        
        return wrapper
    
    if func is None:
        return decorator
    else:
        return decorator(func)


def permission_required(
    resource: Union[ResourceType, str],
    action: Union[Action, str]
):
    """
    Decorator to require specific permission.
    
    Args:
        resource: Resource type
        action: Action to perform
    
    Returns:
        Decorator function
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get current user from kwargs (should be added by auth_required)
            current_user = kwargs.get('current_user')
            
            if not current_user:
                # Try to get from request
                request = None
                for arg in args:
                    if isinstance(arg, Request):
                        request = arg
                        break
                
                if request:
                    current_user = await get_current_user_optional(request)
                
                if not current_user:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Authentication required"
                    )
            
            # Check permission
            try:
                current_user.require_permission(resource, action)
            except InsufficientPermissionsError as e:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=str(e.detail)
                )
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


class AuthMiddleware:
    """Authentication middleware for FastAPI."""
    
    def __init__(self, app):
        self.app = app
    
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        
        request = Request(scope, receive)
        
        # Add auth context to request state
        request.state.auth_user = None
        
        # Try to get current user
        try:
            current_user = await get_current_user_optional(request)
            request.state.auth_user = current_user
        except Exception:
            pass
        
        await self.app(scope, receive, send)


def create_auth_response(
    access_token: str,
    refresh_token: str,
    user_data: Dict[str, Any],
    response: Response,
    message: str = "Authentication successful"
) -> Dict[str, Any]:
    """
    Create authentication response with cookies.
    
    Args:
        access_token: JWT access token
        refresh_token: JWT refresh token
        user_data: User information
        response: FastAPI response object
        message: Response message
    
    Returns:
        Response data dictionary
    """
    # Set secure cookies
    token_cookie_manager.set_auth_cookies(response, access_token, refresh_token, user_data)
    
    return {
        "success": True,
        "message": message,
        "data": {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": config.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "user": user_data
        }
    }


def create_error_response(
    error: Exception,
    status_code: int = status.HTTP_400_BAD_REQUEST
) -> JSONResponse:
    """
    Create standardized error response.
    
    Args:
        error: Exception that occurred
        status_code: HTTP status code
    
    Returns:
        JSON error response
    """
    error_data = {
        "success": False,
        "error": {
            "message": str(error),
            "type": error.__class__.__name__
        }
    }
    
    # Add error code if available
    if hasattr(error, 'error_code'):
        error_data["error"]["code"] = error.error_code
    
    return JSONResponse(
        status_code=status_code,
        content=error_data
    )


# Exception handlers for FastAPI
async def auth_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle authentication-related exceptions."""
    if isinstance(exc, TokenExpiredError):
        return create_error_response(exc, status.HTTP_401_UNAUTHORIZED)
    elif isinstance(exc, TokenInvalidError):
        return create_error_response(exc, status.HTTP_401_UNAUTHORIZED)
    elif isinstance(exc, InsufficientPermissionsError):
        return create_error_response(exc, status.HTTP_403_FORBIDDEN)
    elif isinstance(exc, RateLimitExceededError):
        return create_error_response(exc, status.HTTP_429_TOO_MANY_REQUESTS)
    else:
        return create_error_response(exc, status.HTTP_500_INTERNAL_SERVER_ERROR)


# Convenience dependency aliases
auth_dependency = get_current_user
optional_auth_dependency = get_current_user_optional
admin_dependency = get_admin_user
moderator_dependency = get_moderator_user
