"""
Social authentication service for OAuth providers.
"""

from typing import Dict, Any, Optional, Union
from auth.services.base_auth_service import BaseAuthService
from auth.models.user import User
from auth.managers.user_manager import UserManager
from auth.managers.token_manager import TokenManager
from auth.providers.base import BaseOAuthProvider
from auth.providers.google import GoogleOAuthProvider
from auth.providers.azure import AzureOAuthProvider
from auth.exceptions.auth_exceptions import ProviderError, ValidationError
from auth.utils.security import SecurityUtils
from fastapi import Response
import json


class SocialAuthService(BaseAuthService):
    """
    Social authentication service for OAuth providers.

    Manages social login flows for Google, Azure, and other OAuth providers.
    """

    def __init__(
        self,
        user_manager: UserManager,
        token_manager: TokenManager,
        google_provider: GoogleOAuthProvider,
        azure_provider: AzureOAuthProvider,
    ):
        """Initialize with required managers and providers."""
        super().__init__()
        self._user_manager = user_manager
        self._token_manager = token_manager

        # Register OAuth providers
        self._providers: Dict[str, BaseOAuthProvider] = {
            "google": google_provider,
            "azure": azure_provider,
        }

    def get_provider(self, provider_name: str) -> BaseOAuthProvider:
        """Get OAuth provider by name."""
        provider = self._providers.get(provider_name.lower())
        if not provider:
            raise ProviderError(f"Unsupported provider: {provider_name}", provider_name)
        return provider

    def get_auth_url(self, provider_name: str, state: Optional[str] = None) -> str:
        """
        Get OAuth authorization URL for a provider.

        Args:
            provider_name: Name of the OAuth provider
            state: Optional state parameter for CSRF protection

        Returns:
            Authorization URL

        Raises:
            ProviderError: If provider is not supported
        """
        provider = self.get_provider(provider_name)
        return provider.get_auth_url(state)

    async def authenticate(
        self, credentials: Dict[str, Any], set_cookies: bool = False
    ) -> Union[Dict[str, Any], Response]:
        """
        Authenticate user with OAuth authorization code.

        Args:
            credentials: Dict with 'provider', 'code', and optional 'state'
            set_cookies: Whether to set HTTP cookies for tokens

        Returns:
            Dict with user info and tokens, or Response object if set_cookies=True

        Raises:
            ProviderError: If OAuth flow fails
            ValidationError: If input validation fails
        """
        self._validate_required_fields(credentials, ["provider", "code"])

        provider_name = credentials.get("provider")
        auth_code = credentials.get("code")
        state = credentials.get("state")

        try:
            # Get provider
            provider = self.get_provider(provider_name)

            token_response = await provider.exchange_code_async(auth_code, state)
            access_token = token_response.get("access_token")
            id_token = token_response.get("id_token")

            user_info = None
            if id_token:
                try:
                    # Verify ID token and use it as primary source of user info
                    id_token_payload = self._security_utils.verify_provider_id_token(
                        id_token, provider_name
                    )
                    user_info = self._extract_user_info_from_id_token(
                        provider_name, id_token_payload
                    )
                except Exception as e:
                    # Log the error but don't fail completely - fall back to userinfo endpoint
                    print(f"[WARNING] ID token verification failed: {e}")
                    user_info = None

            # Fall back to userinfo endpoint if ID token verification failed or no ID token
            if not user_info:
                user_info = await provider.get_user_info_async(access_token)

            # Find or create user
            user = await self._find_or_create_user_async(provider_name, user_info)

            # Generate tokens
            tokens = await self._token_manager.generate_token_pair_async(user.id)

            response_dict = self._format_auth_response(
                user,
                tokens["access"].token,
                tokens["refresh"].token,
                {"provider": provider_name},
            )

            if set_cookies:
                return self._create_cookie_response(
                    response_dict, tokens["access"].token, tokens["refresh"].token
                )

            return response_dict

        except Exception as e:
            if isinstance(e, (ProviderError, ValidationError)):
                raise
            self._handle_auth_error(e, f"social authentication ({provider_name})")
            raise ProviderError(
                f"Social authentication failed: {str(e)}", provider_name
            )

    def _extract_user_info_from_id_token(
        self, provider_name: str, id_token_payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract user info from verified ID token payload."""
        if provider_name.lower() == "google":
            return {
                "id": id_token_payload.get("sub"),
                "email": id_token_payload.get("email"),
                "first_name": id_token_payload.get("given_name"),
                "last_name": id_token_payload.get("family_name"),
                "name": id_token_payload.get("name"),
                "picture": id_token_payload.get("picture"),
                "verified_email": id_token_payload.get("email_verified", False),
            }
        elif provider_name.lower() == "azure":
            return {
                "id": id_token_payload.get("oid") or id_token_payload.get("sub"),
                "email": id_token_payload.get("email")
                or id_token_payload.get("preferred_username"),
                "first_name": id_token_payload.get("given_name"),
                "last_name": id_token_payload.get("family_name"),
                "name": id_token_payload.get("name"),
                "job_title": id_token_payload.get("jobTitle"),
                "tenant_id": id_token_payload.get("tid"),
            }
        else:
            # Generic extraction for other providers
            return {
                "id": id_token_payload.get("sub"),
                "email": id_token_payload.get("email"),
                "first_name": id_token_payload.get("given_name"),
                "last_name": id_token_payload.get("family_name"),
                "name": id_token_payload.get("name"),
            }

    async def authenticate_async(self, credentials: Dict[str, Any]) -> Dict[str, Any]:
        """Authenticate user with OAuth authorization code (async)."""
        provider_name = credentials.get("provider")
        auth_code = credentials.get("code")
        state = credentials.get("state")

        if not provider_name or not auth_code:
            raise ValidationError("Provider and authorization code are required")

        try:
            # Get provider
            provider = self.get_provider(provider_name)

            # Exchange authorization code for access token
            access_token = await provider.exchange_code_async(auth_code, state)

            # Get user info from provider
            user_info = await provider.get_user_info_async(access_token)

            # Find or create user
            user = await self._find_or_create_user_async(provider_name, user_info)

            # Generate tokens
            tokens = await self._token_manager.generate_token_pair_async(user.id)

            return {
                "user": user,
                "access_token": tokens["access"].token,
                "refresh_token": tokens["refresh"].token,
                "token_type": "bearer",
                "provider": provider_name,
            }

        except Exception as e:
            if isinstance(e, (ProviderError, ValidationError)):
                raise
            raise ProviderError(
                f"Social authentication failed: {str(e)}", provider_name
            )

    def register(self, user_data: Dict[str, Any]) -> User:
        """
        Register is handled automatically during social authentication.
        This method is not typically used for social auth.
        """
        raise NotImplementedError(
            "Social registration is handled automatically during authentication"
        )

    async def register_async(self, user_data: Dict[str, Any]) -> User:
        """Register is handled automatically during social authentication (async)."""
        raise NotImplementedError(
            "Social registration is handled automatically during authentication"
        )

    def link_provider(
        self,
        user_id: str,
        provider_name: str,
        auth_code: str,
        state: Optional[str] = None,
    ) -> User:
        """
        Link a social provider to an existing user account.

        Args:
            user_id: ID of the existing user
            provider_name: Name of the OAuth provider
            auth_code: Authorization code from provider
            state: Optional state parameter

        Returns:
            Updated User object

        Raises:
            ProviderError: If OAuth flow fails
        """
        try:
            # Get provider
            provider = self.get_provider(provider_name)

            # Exchange authorization code for access token
            access_token = provider.exchange_code(auth_code, state)

            # Get user info from provider
            user_info = provider.get_user_info(access_token)

            # Check if this social account is already linked to another user
            existing_user = self._user_manager.get_user_by_social_id(
                provider_name, user_info["id"]
            )
            if existing_user and existing_user.id != user_id:
                raise ProviderError(
                    f"This {provider_name} account is already linked to another user",
                    provider_name,
                )

            # Link provider to user
            user = self._user_manager.link_social_provider(
                user_id, provider_name, user_info["id"]
            )

            return user

        except Exception as e:
            if isinstance(e, ProviderError):
                raise
            raise ProviderError(
                f"Failed to link {provider_name} account: {str(e)}", provider_name
            )

    async def link_provider_async(
        self,
        user_id: str,
        provider_name: str,
        auth_code: str,
        state: Optional[str] = None,
    ) -> User:
        """Link a social provider to an existing user account (async)."""
        try:
            # Get provider
            provider = self.get_provider(provider_name)

            # Exchange authorization code for access token
            access_token = await provider.exchange_code_async(auth_code, state)

            # Get user info from provider
            user_info = await provider.get_user_info_async(access_token)

            # Check if this social account is already linked to another user
            existing_user = await self._user_manager.get_user_by_social_id_async(
                provider_name, user_info["id"]
            )
            if existing_user and existing_user.id != user_id:
                raise ProviderError(
                    f"This {provider_name} account is already linked to another user",
                    provider_name,
                )

            # Link provider to user
            user = await self._user_manager.link_social_provider_async(
                user_id, provider_name, user_info["id"]
            )

            return user

        except Exception as e:
            if isinstance(e, ProviderError):
                raise
            raise ProviderError(
                f"Failed to link {provider_name} account: {str(e)}", provider_name
            )

    def unlink_provider(self, user_id: str, provider_name: str) -> User:
        """
        Unlink a social provider from a user account.

        Args:
            user_id: ID of the user
            provider_name: Name of the provider to unlink

        Returns:
            Updated User object
        """
        return self._user_manager.unlink_social_provider(user_id, provider_name)

    async def unlink_provider_async(self, user_id: str, provider_name: str) -> User:
        """Unlink a social provider from a user account (async)."""
        return await self._user_manager.unlink_social_provider_async(
            user_id, provider_name
        )

    def _find_or_create_user(
        self, provider_name: str, user_info: Dict[str, Any]
    ) -> User:
        """Find existing user or create new one based on social provider info."""
        provider_user_id = user_info["id"]
        email = user_info.get("email")

        # First, try to find user by social provider ID
        user = self._user_manager.get_user_by_social_id(provider_name, provider_user_id)
        if user:
            return user

        # If not found and email is available, try to find by email
        if email:
            try:
                user = self._user_manager.get_user_by_email(email)
                # Link this social provider to the existing user
                user = self._user_manager.link_social_provider(
                    user.id, provider_name, provider_user_id
                )
                return user
            except:
                # User with this email doesn't exist, create new one
                pass

        # Create new user
        social_ids = {provider_name: provider_user_id}
        user = self._user_manager.create_user(
            email=email or f"{provider_user_id}@{provider_name}.social",
            first_name=user_info.get("first_name"),
            last_name=user_info.get("last_name"),
            social_ids=social_ids,
        )

        return user

    async def _find_or_create_user_async(
        self, provider_name: str, user_info: Dict[str, Any]
    ) -> User:
        """Find existing user or create new one based on social provider info (async)."""
        provider_user_id = user_info["id"]
        email = user_info.get("email")

        # First, try to find user by social provider ID
        user = await self._user_manager.get_user_by_social_id_async(
            provider_name, provider_user_id
        )
        if user:
            return user

        # If not found and email is available, try to find by email
        if email:
            try:
                user = await self._user_manager.get_user_by_email_async(email)
                # Link this social provider to the existing user
                user = await self._user_manager.link_social_provider_async(
                    user.id, provider_name, provider_user_id
                )
                return user
            except:
                # User with this email doesn't exist, create new one
                pass

        # Create new user
        social_ids = {provider_name: provider_user_id}
        user = await self._user_manager.create_user_async(
            email=email or f"{provider_user_id}@{provider_name}.social",
            first_name=user_info.get("first_name"),
            last_name=user_info.get("last_name"),
            social_ids=social_ids,
        )

        return user

    def get_supported_providers(self) -> list[str]:
        """Get list of supported OAuth providers."""
        return list(self._providers.keys())
