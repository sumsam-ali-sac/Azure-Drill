"""
FastAPI dependencies for authentication service.
"""

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional
from root.auth.managers.user_manager import UserManager
from root.auth.managers.token_manager import TokenManager
from root.auth.repositories.user_repository import UserRepository
from root.auth.repositories.token_repository import TokenRepository
from root.auth.services.auth_service import AuthService
from root.auth.services.social_auth_service import SocialAuthService
from root.auth.services.otp_service import OTPService
from root.auth.providers.google import GoogleOAuthProvider
from root.auth.providers.azure import AzureOAuthProvider
from root.auth.utils.security import SecurityUtils
from root.auth.models.user import User
from root.auth.exceptions.auth_exceptions import InvalidTokenError

# Security scheme
security = HTTPBearer()


# Dependency injection setup
def get_security_utils() -> SecurityUtils:
    """Get SecurityUtils instance."""
    return SecurityUtils()


def get_user_repository() -> UserRepository:
    """Get UserRepository instance."""
    return UserRepository()


def get_token_repository() -> TokenRepository:
    """Get TokenRepository instance."""
    return TokenRepository()


def get_user_manager(
    user_repo: UserRepository = Depends(get_user_repository),
) -> UserManager:
    """Get UserManager instance."""
    return UserManager(user_repo)


def get_token_manager(
    token_repo: TokenRepository = Depends(get_token_repository),
) -> TokenManager:
    """Get TokenManager instance."""
    return TokenManager(token_repo)


def get_google_provider() -> GoogleOAuthProvider:
    """Get GoogleOAuthProvider instance."""
    return GoogleOAuthProvider()


def get_azure_provider() -> AzureOAuthProvider:
    """Get AzureOAuthProvider instance."""
    return AzureOAuthProvider()


def get_auth_service(
    user_manager: UserManager = Depends(get_user_manager),
    token_manager: TokenManager = Depends(get_token_manager),
    security_utils: SecurityUtils = Depends(get_security_utils),
) -> AuthService:
    """Get AuthService instance."""
    return AuthService(user_manager, token_manager, security_utils)


def get_social_auth_service(
    user_manager: UserManager = Depends(get_user_manager),
    token_manager: TokenManager = Depends(get_token_manager),
    google_provider: GoogleOAuthProvider = Depends(get_google_provider),
    azure_provider: AzureOAuthProvider = Depends(get_azure_provider),
) -> SocialAuthService:
    """Get SocialAuthService instance."""
    return SocialAuthService(
        user_manager, token_manager, google_provider, azure_provider
    )


def get_otp_service(
    user_manager: UserManager = Depends(get_user_manager),
    token_manager: TokenManager = Depends(get_token_manager),
    security_utils: SecurityUtils = Depends(get_security_utils),
) -> OTPService:
    """Get OTPService instance."""
    return OTPService(user_manager, token_manager, security_utils)


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    token_manager: TokenManager = Depends(get_token_manager),
    user_manager: UserManager = Depends(get_user_manager),
) -> User:
    """Get current authenticated user from JWT token."""
    try:
        # Try to get token from Authorization header
        token = credentials.credentials

        # If no token in header, try to get from cookies
        if not token:
            token = request.cookies.get("access_token")

        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="No authentication token provided",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Validate token
        payload = token_manager.validate_token(token)
        user_id = payload.get("user_id")

        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Get user
        user = user_manager.get_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account is deactivated",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return user

    except InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_optional_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    token_manager: TokenManager = Depends(get_token_manager),
    user_manager: UserManager = Depends(get_user_manager),
) -> Optional[User]:
    """Get current authenticated user if token is provided (optional)."""
    try:
        if not credentials:
            # Try to get from cookies
            token = request.cookies.get("access_token")
            if not token:
                return None
        else:
            token = credentials.credentials

        # Validate token
        payload = token_manager.validate_token(token)
        user_id = payload.get("user_id")

        if not user_id:
            return None

        # Get user
        user = user_manager.get_by_id(user_id)
        if not user or not user.is_active:
            return None

        return user

    except Exception:
        return None
