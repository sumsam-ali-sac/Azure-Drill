"""
Basic authentication API routes.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from auth_service.services.auth_service import AuthService
from auth_service.api.dependencies import get_auth_service, get_current_user
from auth_service.models.user import User
from auth_service.exceptions.auth_exceptions import (
    ValidationError, 
    InvalidCredentialsError, 
    UserAlreadyExistsError
)
from auth_service.api.models.auth_models import (
    LoginRequest,
    RegisterRequest,
    ChangePasswordRequest,
    PasswordResetRequest,
    PasswordResetConfirmRequest,
    LogoutRequest,
    AuthResponse,
    UserResponse
)
from auth_service.api.models.common_models import SuccessResponse

router = APIRouter()

@router.post("/login")
async def login(
    request: LoginRequest,
    http_request: Request,
    auth_service: AuthService = Depends(get_auth_service)
):
    """
    Authenticate user with email and password.
    
    Returns JWT tokens for authenticated access.
    """
    try:
        credentials = {
            "email": request.email,
            "password": request.password
        }
        
        result = await auth_service.authenticate_async(credentials, request.set_cookies)
        
        # If cookies are requested, return the Response object
        if request.set_cookies:
            return result
        
        return result
        
    except InvalidCredentialsError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Authentication failed")

@router.post("/register", response_model=UserResponse)
async def register(
    request: RegisterRequest,
    auth_service: AuthService = Depends(get_auth_service)
):
    """
    Register a new user with email and password.
    
    Returns the created user information.
    """
    try:
        user_data = {
            "email": request.email,
            "password": request.password,
            "first_name": request.first_name,
            "last_name": request.last_name
        }
        
        user = await auth_service.register_async(user_data)
        return UserResponse(user=user.dict())
        
    except UserAlreadyExistsError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Registration failed")

@router.post("/change-password", response_model=SuccessResponse)
async def change_password(
    request: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service)
):
    """
    Change password for the authenticated user.
    
    Requires current password for verification.
    """
    try:
        success = await auth_service.change_password_async(
            current_user.id, 
            request.old_password, 
            request.new_password
        )
        
        if success:
            return SuccessResponse(success=True, message="Password changed successfully")
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Failed to change password")
            
    except InvalidCredentialsError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Password change failed")

@router.post("/reset-password", response_model=SuccessResponse)
async def reset_password(
    request: PasswordResetRequest,
    auth_service: AuthService = Depends(get_auth_service)
):
    """
    Initiate password reset process.
    
    Sends a password reset token (in production, this would be sent via email).
    """
    try:
        reset_token = await auth_service.reset_password_async(request.email)
        
        # In production, you would send this token via email instead of returning it
        return SuccessResponse(
            success=True, 
            message=f"Password reset initiated. Token: {reset_token}"
        )
        
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        # Don't reveal if user exists or not for security
        return SuccessResponse(success=True, message="If the email exists, a reset link has been sent")

@router.post("/reset-password/confirm", response_model=SuccessResponse)
async def confirm_password_reset(
    request: PasswordResetConfirmRequest,
    auth_service: AuthService = Depends(get_auth_service)
):
    """
    Confirm password reset with token and new password.
    
    Completes the password reset process.
    """
    try:
        success = await auth_service.confirm_password_reset_async(
            request.reset_token, 
            request.new_password
        )
        
        if success:
            return SuccessResponse(success=True, message="Password reset successfully")
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Failed to reset password")
            
    except InvalidCredentialsError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Password reset failed")

@router.post("/logout")
async def logout(
    request: LogoutRequest,
    http_request: Request,
    current_user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service)
):
    """
    Logout the authenticated user.
    
    Revokes the current access token.
    """
    try:
        # Get token from Authorization header or cookies
        token = None
        auth_header = http_request.headers.get("authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
        else:
            token = http_request.cookies.get("access_token")
        
        if not token:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No token to logout")
        
        result = await auth_service.logout_async(token, request.clear_cookies)
        
        # If cookies are cleared, return the Response object
        if request.clear_cookies:
            return result
        
        return SuccessResponse(success=True, message="Logged out successfully")
        
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Logout failed")

@router.post("/logout-all", response_model=SuccessResponse)
async def logout_all_devices(
    current_user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service)
):
    """
    Logout user from all devices.
    
    Revokes all tokens for the authenticated user.
    """
    try:
        revoked_count = await auth_service.logout_all_devices_async(current_user.id)
        return SuccessResponse(
            success=True, 
            message=f"Logged out from {revoked_count} devices"
        )
        
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Logout from all devices failed")

# Health check endpoint for auth service
@router.get("/health")
async def auth_health_check():
    """Health check for authentication service."""
    return {
        "status": "healthy",
        "service": "email-password-authentication",
        "features": [
            "User registration",
            "Email/password login",
            "Password change",
            "Password reset",
            "Token-based authentication"
        ]
    }
