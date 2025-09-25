"""
Social authentication API routes.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from typing import Optional
from root.auth.api.models.social_models import (
    AuthUrlRequest,
    AuthUrlResponse,
    LinkProviderRequest,
    ProvidersResponse,
    SocialAuthRequest,
    SocialAuthResponse,
    UnlinkProviderRequest,
    UserResponse,
)
from root.auth.services.social_auth_service import SocialAuthService
from root.auth.api.dependencies import get_social_auth_service, get_current_user
from root.auth.models.user import User
from root.auth.exceptions.auth_exceptions import (
    ProviderError,
    ValidationError,
    InvalidTokenError,
    TokenExpiredError,
    UserNotFoundError,
    UserAlreadyExistsError,
    InvalidOTPError,
    AuthServiceError,
    ProviderAlreadyLinkedError,
    ProviderNotLinkedError,
)

router = APIRouter()


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
    except ProviderError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except AuthServiceError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )
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
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except AuthServiceError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get authorization URL",
        )


@router.post("/authenticate", response_model=SocialAuthResponse)
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

        if request.set_cookies:
            return result

        return result

    except ProviderError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except InvalidTokenError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except TokenExpiredError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    except UserNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except UserAlreadyExistsError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except InvalidOTPError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except AuthServiceError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )
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
    except InvalidTokenError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except UserNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except ProviderAlreadyLinkedError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except AuthServiceError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )
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

    except UserNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except ProviderNotLinkedError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except AuthServiceError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to unlink provider",
        )


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

    except ProviderError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except InvalidTokenError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except TokenExpiredError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    except UserNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except UserAlreadyExistsError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except AuthServiceError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )
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

    except ProviderError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except InvalidTokenError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except TokenExpiredError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    except UserNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except UserAlreadyExistsError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except AuthServiceError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Azure authentication failed",
        )


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
