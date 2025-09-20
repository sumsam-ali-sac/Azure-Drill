"""
Social authentication API routes.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, Field
from typing import Optional
from auth.services.social_auth_service import SocialAuthService
from auth.api.dependencies import get_social_auth_service, get_current_user
from auth.models.user import User
from auth.exceptions.auth_exceptions import ProviderError, ValidationError

router = APIRouter()


# Request/Response models
class AuthUrlRequest(BaseModel):
    """Request model for getting OAuth authorization URL."""

    provider: str = Field(..., description="OAuth provider name (google, azure)")
    state: Optional[str] = Field(
        None, description="Optional state parameter for CSRF protection"
    )


class AuthUrlResponse(BaseModel):
    """Response model for OAuth authorization URL."""

    auth_url: str = Field(..., description="OAuth authorization URL")
    provider: str = Field(..., description="OAuth provider name")


class SocialAuthRequest(BaseModel):
    """Request model for social authentication."""

    provider: str = Field(..., description="OAuth provider name (google, azure)")
    code: str = Field(..., description="Authorization code from OAuth provider")
    state: Optional[str] = Field(
        None, description="State parameter for CSRF protection"
    )
    set_cookies: bool = Field(
        default=False, description="Whether to set authentication cookies"
    )


class LinkProviderRequest(BaseModel):
    """Request model for linking social provider."""

    provider: str = Field(..., description="OAuth provider name (google, azure)")
    code: str = Field(..., description="Authorization code from OAuth provider")
    state: Optional[str] = Field(
        None, description="State parameter for CSRF protection"
    )


class UnlinkProviderRequest(BaseModel):
    """Request model for unlinking social provider."""

    provider: str = Field(..., description="OAuth provider name to unlink")


class AuthResponse(BaseModel):
    """Response model for social authentication."""

    user: dict = Field(..., description="User information")
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(..., description="Token type (bearer)")
    provider: str = Field(..., description="OAuth provider used")


class UserResponse(BaseModel):
    """Response model for user information."""

    user: dict = Field(..., description="User information")


class ProvidersResponse(BaseModel):
    """Response model for supported providers."""

    providers: list[str] = Field(..., description="List of supported OAuth providers")


class SuccessResponse(BaseModel):
    """Generic success response."""

    success: bool = Field(..., description="Whether operation was successful")
    message: str = Field(..., description="Success message")


@router.get("/providers", response_model=ProvidersResponse)
async def get_supported_providers(
    social_service: SocialAuthService = Depends(get_social_auth_service),
):
    """
    Get list of supported OAuth providers.

    Returns the available social authentication providers.
    """
    try:
        providers = social_service.get_supported_providers()
        return ProvidersResponse(providers=providers)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get providers",
        )


@router.post("/auth-url", response_model=AuthUrlResponse)
async def get_auth_url(
    request: AuthUrlRequest,
    social_service: SocialAuthService = Depends(get_social_auth_service),
):
    """
    Get OAuth authorization URL for a provider.

    Returns the URL where users should be redirected to authenticate with the provider.
    """
    try:
        auth_url = social_service.get_auth_url(request.provider, request.state)
        return AuthUrlResponse(auth_url=auth_url, provider=request.provider)
    except ProviderError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get authorization URL",
        )


@router.post("/authenticate")
async def authenticate_social(
    request: SocialAuthRequest,
    http_request: Request,
    social_service: SocialAuthService = Depends(get_social_auth_service),
):
    """
    Authenticate user with OAuth authorization code.

    Exchanges the authorization code for user information and returns JWT tokens.
    """
    try:
        credentials = {
            "provider": request.provider,
            "code": request.code,
            "state": request.state,
        }

        result = await social_service.authenticate(credentials, request.set_cookies)

        # If cookies are requested, return the Response object
        if request.set_cookies:
            return result

        return result

    except ProviderError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Social authentication failed",
        )


@router.post("/link", response_model=UserResponse)
async def link_provider(
    request: LinkProviderRequest,
    current_user: User = Depends(get_current_user),
    social_service: SocialAuthService = Depends(get_social_auth_service),
):
    """
    Link a social provider to the authenticated user's account.

    Allows users to add additional social login methods to their existing account.
    """
    try:
        user = await social_service.link_provider_async(
            current_user.id, request.provider, request.code, request.state
        )
        return UserResponse(user=user.dict())

    except ProviderError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to link provider",
        )


@router.post("/unlink", response_model=UserResponse)
async def unlink_provider(
    request: UnlinkProviderRequest,
    current_user: User = Depends(get_current_user),
    social_service: SocialAuthService = Depends(get_social_auth_service),
):
    """
    Unlink a social provider from the authenticated user's account.

    Removes a social login method from the user's account.
    """
    try:
        user = await social_service.unlink_provider_async(
            current_user.id, request.provider
        )
        return UserResponse(user=user.dict())

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to unlink provider",
        )


# Provider-specific callback endpoints (for development/testing)
@router.get("/google/callback")
async def google_callback(
    code: str,
    state: Optional[str] = None,
    social_service: SocialAuthService = Depends(get_social_auth_service),
):
    """
    Google OAuth callback endpoint (for development/testing).

    In production, this would typically be handled by your frontend application.
    """
    try:
        credentials = {"provider": "google", "code": code, "state": state}

        result = await social_service.authenticate(credentials)
        return result

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google authentication failed",
        )


@router.get("/azure/callback")
async def azure_callback(
    code: str,
    state: Optional[str] = None,
    social_service: SocialAuthService = Depends(get_social_auth_service),
):
    """
    Azure OAuth callback endpoint (for development/testing).

    In production, this would typically be handled by your frontend application.
    """
    try:
        credentials = {"provider": "azure", "code": code, "state": state}

        result = await social_service.authenticate(credentials)
        return result

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Azure authentication failed",
        )


# Health check endpoint for social auth service
@router.get("/health")
async def social_health_check():
    """Health check for social authentication service."""
    return {
        "status": "healthy",
        "service": "social-authentication",
        "features": [
            "Google OAuth",
            "Azure OAuth",
            "Provider linking/unlinking",
            "Authorization URL generation",
        ],
    }
