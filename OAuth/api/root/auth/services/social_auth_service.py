"""
Social authentication service for OAuth providers.
"""

from typing import Dict, Any, Optional, Union
from root.auth.services.base_auth_service import BaseAuthService
from root.auth.models.user import User
from root.auth.managers.user_manager import UserManager
from root.auth.managers.token_manager import TokenManager
from root.auth.providers.base import BaseOAuthProvider
from root.auth.providers.google import GoogleOAuthProvider
from root.auth.providers.azure import AzureOAuthProvider
from root.auth.exceptions.auth_exceptions import ProviderError, ValidationError
from root.auth.utils.security import SecurityUtils
from fastapi import Response
import logging

# Configure logging
logger = logging.getLogger(__name__)


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
        self._security_utils = (
            security_utils  # Kept for compatibility, prefer _get_security_utils()
        )
        self._providers: Dict[str, BaseOAuthProvider] = {
            "google": google_provider,
            "azure": azure_provider,
        }

    def get_provider(self, provider_name: str) -> BaseOAuthProvider:
        """Get OAuth provider by name."""
        if not isinstance(provider_name, str):
            raise ValidationError("Provider name must be a string")
        provider_name = provider_name.lower()
        provider = self._providers.get(provider_name)
        if not provider:
            logger.error(f"Unsupported provider requested: {provider_name}")
            raise ProviderError(f"Unsupported provider: {provider_name}", provider_name)
        return provider

    def get_auth_url(self, provider_name: str, state: Optional[str] = None) -> str:
        """
        Get OAuth authorization URL for a provider.
        """
        if not isinstance(provider_name, str):
            raise ValidationError("Provider name must be a string")
        if state is not None and not isinstance(state, str):
            raise ValidationError("State must be a string or None")
        try:
            provider = self.get_provider(provider_name)
            url = provider.get_auth_url(state)
            logger.info(f"Generated auth URL for provider {provider_name}")
            return url
        except Exception as e:
            logger.error(
                f"Failed to generate auth URL for {provider_name}: {str(e)}",
                exc_info=True,
            )
            raise ProviderError(
                f"Failed to generate auth URL for {provider_name}", provider_name
            ) from e

    async def authenticate(
        self, credentials: Dict[str, Any], set_cookies: bool = False
    ) -> Union[Dict[str, Any], Response]:
        """
        Authenticate user with OAuth authorization code.
        """
        if not isinstance(credentials, dict):
            raise ValidationError("Credentials must be a dictionary")
        self._validate_required_fields(credentials, ["provider", "code"])

        provider_name = credentials.get("provider")
        auth_code = credentials.get("code")
        state = credentials.get("state")

        if not isinstance(provider_name, str) or not isinstance(auth_code, str):
            raise ValidationError("Provider and code must be strings")
        if state is not None and not isinstance(state, str):
            raise ValidationError("State must be a string or None")

        try:
            provider = self.get_provider(provider_name)
            token_response = await provider.exchange_code_async(auth_code, state)

            if not token_response.get("access_token"):
                logger.error(f"Failed to obtain access token for {provider_name}")
                raise ProviderError("Failed to obtain access token", provider_name)

            access_token = token_response["access_token"]
            id_token = token_response.get("id_token")

            user_info = None
            if id_token:
                try:
                    id_token_payload = (
                        self._get_security_utils().verify_provider_id_token(
                            id_token, provider_name
                        )
                    )
                    user_info = self._extract_user_info_from_id_token(
                        provider_name, id_token_payload
                    )
                except Exception as e:
                    logger.warning(
                        f"ID token verification failed for {provider_name}: {str(e)}",
                        exc_info=True,
                    )
                    user_info = None

            if not user_info:
                user_info = await provider.get_user_info_async(access_token)

            if not user_info or not user_info.get("id"):
                logger.error(f"Invalid user info received from {provider_name}")
                raise ValidationError("Invalid user info received from provider")

            user = await self._find_or_create_user_async(provider_name, user_info)
            tokens = await self._token_manager.generate_token_pair_async(user.id)

            logger.info(f"User authenticated via {provider_name} with ID {user.id}")
            return self._format_auth_response(
                user,
                tokens["access"].token,
                tokens["refresh"].token,
                additional_data={"provider": provider_name},
                set_cookies=set_cookies,
            )

        except Exception as e:
            if isinstance(e, (ProviderError, ValidationError)):
                raise
            logger.error(
                f"Social authentication failed for {provider_name}: {str(e)}",
                exc_info=True,
            )
            raise ProviderError(
                f"Social authentication failed: {str(e)}", provider_name
            ) from e

    def _extract_user_info_from_id_token(
        self, provider_name: str, id_token_payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract user info from verified ID token payload."""
        if not isinstance(provider_name, str):
            raise ValidationError("Provider name must be a string")
        if not isinstance(id_token_payload, dict):
            raise ValidationError("ID token payload must be a dictionary")

        provider_name = provider_name.lower()
        required_fields = ["sub"]
        missing_fields = [
            field for field in required_fields if not id_token_payload.get(field)
        ]
        if missing_fields:
            logger.error(
                f"Missing required ID token fields for {provider_name}: {', '.join(missing_fields)}"
            )
            raise ValidationError(
                f"Missing required ID token fields: {', '.join(missing_fields)}"
            )

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

        return {k: v for k, v in user_info.items() if v is not None}

    def register(self, user_data: Dict[str, Any]) -> User:
        """
        Register is handled automatically during social authentication.
        """
        logger.warning("Attempted to call register on SocialAuthService")
        raise NotImplementedError(
            "Social registration is handled automatically during authentication"
        )

    async def register_async(self, user_data: Dict[str, Any]) -> User:
        """Register is handled automatically during social authentication (async)."""
        logger.warning("Attempted to call register_async on SocialAuthService")
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
        if (
            not isinstance(user_id, str)
            or not isinstance(provider_name, str)
            or not isinstance(auth_code, str)
        ):
            raise ValidationError(
                "User ID, provider name, and auth code must be strings"
            )
        if state is not None and not isinstance(state, str):
            raise ValidationError("State must be a string or None")

        try:
            provider = self.get_provider(provider_name)
            token_response = await provider.exchange_code_async(auth_code, state)

            if not token_response.get("access_token"):
                logger.error(
                    f"Failed to obtain access token for {provider_name} during linking"
                )
                raise ProviderError("Failed to obtain access token", provider_name)

            user_info = await provider.get_user_info_async(
                token_response["access_token"]
            )

            if not user_info or not user_info.get("id"):
                logger.error(
                    f"Invalid user info received from {provider_name} during linking"
                )
                raise ValidationError("Invalid user info received from provider")

            existing_user = await self._user_manager.get_user_by_social_id_async(
                provider_name, user_info["id"]
            )
            if existing_user and existing_user.id != user_id:
                logger.warning(
                    f"Linking failed: {provider_name} account already linked to another user"
                )
                raise ProviderError(
                    f"This {provider_name} account is already linked to another user",
                    provider_name,
                )

            user = await self._user_manager.link_social_provider_async(
                user_id, provider_name, user_info["id"]
            )
            logger.info(f"Linked {provider_name} account to user {user_id}")
            return user

        except Exception as e:
            if isinstance(e, (ProviderError, ValidationError)):
                raise
            logger.error(
                f"Failed to link {provider_name} account for user {user_id}: {str(e)}",
                exc_info=True,
            )
            raise ProviderError(
                f"Failed to link {provider_name} account: {str(e)}", provider_name
            ) from e

    async def unlink_provider_async(self, user_id: str, provider_name: str) -> User:
        """Unlink a social provider from a user account."""
        if not isinstance(user_id, str) or not isinstance(provider_name, str):
            raise ValidationError("User ID and provider name must be strings")

        try:
            user = await self._user_manager.unlink_social_provider_async(
                user_id, provider_name
            )
            logger.info(f"Unlinked {provider_name} account from user {user_id}")
            return user
        except Exception as e:
            logger.error(
                f"Failed to unlink {provider_name} account for user {user_id}: {str(e)}",
                exc_info=True,
            )
            raise ProviderError(
                f"Failed to unlink {provider_name} account: {str(e)}", provider_name
            ) from e

    async def _find_or_create_user_async(
        self, provider_name: str, user_info: Dict[str, Any]
    ) -> User:
        """Find existing user or create new one based on social provider info."""
        if not isinstance(provider_name, str) or not isinstance(user_info, dict):
            raise ValidationError(
                "Provider name and user info must be a string and dictionary, respectively"
            )

        provider_user_id = user_info.get("id")
        if not provider_user_id:
            logger.error(f"Missing provider user ID for {provider_name}")
            raise ValidationError("Provider user ID is required")

        email = user_info.get("email")

        try:
            user = await self._user_manager.get_user_by_social_id_async(
                provider_name, provider_user_id
            )
            if user:
                logger.info(
                    f"Found existing user for {provider_name} ID {provider_user_id}"
                )
                return user
        except Exception as e:
            logger.debug(
                f"No user found for {provider_name} ID {provider_user_id}: {str(e)}"
            )
            pass

        if email:
            try:
                user = await self._user_manager.get_user_by_email_async(email)
                user = await self._user_manager.link_social_provider_async(
                    user.id, provider_name, provider_user_id
                )
                logger.info(
                    f"Linked {provider_name} ID {provider_user_id} to existing user with email {email}"
                )
                return user
            except Exception as e:
                logger.debug(f"No user found for email {email}: {str(e)}")
                pass

        social_ids = {provider_name: provider_user_id}
        user = await self._user_manager.create_user_async(
            email=email or f"{provider_user_id}@{provider_name}.social",
            first_name=user_info.get("first_name") or "",
            last_name=user_info.get("last_name") or "",
            social_ids=social_ids,
        )
        logger.info(f"Created new user for {provider_name} ID {provider_user_id}")
        return user

    def get_supported_providers(self) -> list[str]:
        """Get list of supported OAuth providers."""
        providers = list(self._providers.keys())
        logger.debug(f"Retrieved supported providers: {providers}")
        return providers
