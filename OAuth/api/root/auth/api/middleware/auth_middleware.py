"""
Authentication middleware for API endpoints.
"""

from typing import Optional
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from auth.services.auth_service import AuthService
from auth.exceptions.auth_exceptions import AuthServiceError

security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    auth_service: AuthService = Depends(),
) -> dict:
    """
    Get current authenticated user from JWT token.

    Args:
        credentials: HTTP Bearer token credentials
        auth_service: Injected auth service

    Returns:
        User information from token payload

    Raises:
        HTTPException: If token is invalid or expired
    """
    try:
        token = credentials.credentials
        payload = auth.token_manager.validate_token(token)

        # Get user information
        user = auth.user_manager.get_user_by_id(payload["user_id"])
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found"
            )

        return {"user_id": user.id, "email": user.email, "user": user}

    except AuthServiceError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication failed: {e.message}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )


async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    auth_service: AuthService = Depends(),
) -> Optional[dict]:
    """
    Get current user if authenticated, None otherwise.

    Args:
        credentials: Optional HTTP Bearer token credentials
        auth_service: Injected auth service

    Returns:
        User information if authenticated, None otherwise
    """
    if not credentials:
        return None

    try:
        return await get_current_user(credentials, auth_service)
    except HTTPException:
        return None
