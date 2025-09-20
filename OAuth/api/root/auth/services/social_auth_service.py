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
        security_utils: SecurityUtils,
        google_provider: GoogleOAuthProvider,
        azure_provider: AzureOAuthProvider,
    ):
        """Initialize with required managers and providers."""
        super().__init__()
        self._user_manager = user_manager
        self._token_manager = token_manager
        self._security_utils = security_utils
        self._providers: Dict[str, BaseOAuthProvider] = {
            "google": google_provider,
            "azure": azure_provider,
        }

    def get_provider(self, provider_name: str) -> BaseOAuthProvider:
        """Get OAuth provider by name."""
        provider_name = provider_name.lower()
        provider = self._providers.get(provider_name)
        if not provider:
            raise ProviderError(f"Unsupported provider: {provider_name}", provider_name)
        return provider

    def get_auth_url(self, provider_name: str, state: Optional[str] = None) -> str:
        """
        Get OAuth authorization URL for a provider.
        """
        provider = self.get_provider(provider_name)
        return provider.get_auth_url(state)

    async def authenticate(
        self, credentials: Dict[str, Any], set_cookies: bool = False
    ) -> Union[Dict[str, Any], Response]:
        """
        Authenticate user with OAuth authorization code.
        """
        self._validate_required_fields(credentials, ["provider", "code"])

        provider_name = credentials.get("provider")
        auth_code = credentials.get("code")
        state = credentials.get("state")

        try:
            provider = self.get_provider(provider_name)
            token_response = await provider.exchange_code_async(auth_code, state)

            if not token_response.get("access_token"):
                raise ProviderError("Failed to obtain access token", provider_name)

            access_token = token_response["access_token"]
            id_token = token_response.get("id_token")

            user_info = None
            if id_token:
                try:
                    id_token_payload = self._security_utils.verify_provider_id_token(
                        id_token, provider_name
                    )
                    user_info = self._extract_user_info_from_id_token(
                        provider_name, id_token_payload
                    )
                except Exception as e:
                    print(f"[WARNING] ID token verification failed: {e}")
                    user_info = None

            if not user_info:
                user_info = await provider.get_user_info_async(access_token)

            if not user_info or not user_info.get("id"):
                raise ValidationError("Invalid user info received from provider")

            user = await self._find_or_create_user_async(provider_name, user_info)
            tokens = await self._token_manager.generate_token_pair_async(user.id)

            response_dict = self._format_auth_response(
                user,
                tokens["access"].token,
                tokens["refresh"].token,
                {"provider": provider_name},
            )

            if set_cookies:
                response = self._create_cookie_response(
                    response_dict, tokens["access"].token, tokens["refresh"].token
                )
                return response

            return response_dict

        except Exception as e:
            if isinstance(e, (ProviderError, ValidationError)):
                raise
            raise ProviderError(
                f"Social authentication failed: {str(e)}", provider_name
            ) from e

    def _extract_user_info_from_id_token(
        self, provider_name: str, id_token_payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract user info from verified ID token payload."""
        provider_name = provider_name.lower()
        user_info = {
            "id": id_token_payload.get("sub"),
            "email": id_token_payload.get("email"),
            "first_name": id_token_payload.get("given_name"),
            "last_name": id_token_payload.get("family_name"),
            "name": id_token_payload.get("name"),
        }

        if provider_name == "google":
            user_info.update(
                {
                    "picture": id_token_payload.get("picture"),
                    "verified_email": id_token_payload.get("email_verified", False),
                }
            )
        elif provider_name == "azure":
            user_info.update(
                {
                    "id": id_token_payload.get("oid") or id_token_payload.get("sub"),
                    "email": id_token_payload.get("email")
                    or id_token_payload.get("preferred_username"),
                    "job_title": id_token_payload.get("jobTitle"),
                    "tenant_id": id_token_payload.get("tid"),
                }
            )

        return user_info

    # Removed duplicate authenticate_async method as it was redundant
    # The authenticate method above already handles async operations correctly

    def register(self, user_data: Dict[str, Any]) -> User:
        """
        Register is handled automatically during social authentication.
        """
        raise NotImplementedError(
            "Social registration is handled automatically during authentication"
        )

    async def register_async(self, user_data: Dict[str, Any]) -> User:
        """Register is handled automatically during social authentication (async)."""
        raise NotImplementedError(
            "Social registration is handled automatically during authentication"
        )

    async def link_provider(
        self,
        user_id: str,
        provider_name: str,
        auth_code: str,
        state: Optional[str] = None,
    ) -> User:
        """Link a social provider to an existing user account."""
        try:
            provider = self.get_provider(provider_name)
            token_response = await provider.exchange_code_async(auth_code, state)

            if not token_response.get("access_token"):
                raise ProviderError("Failed to obtain access token", provider_name)

            user_info = await provider.get_user_info_async(
                token_response["access_token"]
            )

            if not user_info or not user_info.get("id"):
                raise ValidationError("Invalid user info received from provider")

            existing_user = await self._user_manager.get_user_by_social_id_async(
                provider_name, user_info["id"]
            )
            if existing_user and existing_user.id != user_id:
                raise ProviderError(
                    f"This {provider_name} account is already linked to another user",
                    provider_name,
                )

            user = await self._user_manager.link_social_provider_async(
                user_id, provider_name, user_info["id"]
            )
            return user

        except Exception as e:
            if isinstance(e, ProviderError):
                raise
            raise ProviderError(
                f"Failed to link {provider_name} account: {str(e)}", provider_name
            ) from e

    async def unlink_provider_async(self, user_id: str, provider_name: str) -> User:
        """Unlink a social provider from a user account."""
        try:
            return await self._user_manager.unlink_social_provider_async(
                user_id, provider_name
            )
        except Exception as e:
            raise ProviderError(
                f"Failed to unlink {provider_name} account: {str(e)}", provider_name
            ) from e

    async def _find_or_create_user_async(
        self, provider_name: str, user_info: Dict[str, Any]
    ) -> User:
        """Find existing user or create new one based on social provider info."""
        provider_user_id = user_info.get("id")
        if not provider_user_id:
            raise ValidationError("Provider user ID is required")

        email = user_info.get("email")

        user = await self._user_manager.get_user_by_social_id_async(
            provider_name, provider_user_id
        )
        if user:
            return user

        if email:
            try:
                user = await self._user_manager.get_user_by_email_async(email)
                user = await self._user_manager.link_social_provider_async(
                    user.id, provider_name, provider_user_id
                )
                return user
            except Exception:
                pass

        social_ids = {provider_name: provider_user_id}
        user = await self._user_manager.create_user_async(
            email=email or f"{provider_user_id}@{provider_name}.social",
            first_name=user_info.get("first_name") or "",
            last_name=user_info.get("last_name") or "",
            social_ids=social_ids,
        )
        return user

    def get_supported_providers(self) -> list[str]:
        """Get list of supported OAuth providers."""
        return list(self._providers.keys())
