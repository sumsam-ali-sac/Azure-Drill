"""
OAuth manager for handling social login integrations.
Supports multiple providers with unified interface.
"""

import secrets
import time
from typing import Dict, Any, Optional, List
from urllib.parse import urlencode, parse_qs
import logging

from root.authcommon.config import config
from root.authcommon.exceptions import OAuthError, InvalidStateError
from root.authsecurity.token_utils import JWKSManager
from root.authoauth import GoogleProvider, AzureProvider

logger = logging.getLogger(__name__)


class OAuthManager:
    """
    Unified OAuth manager for social login providers.

    Features:
    - Multiple provider support (Google, Azure, etc.)
    - PKCE (Proof Key for Code Exchange) support
    - State parameter for CSRF protection
    - Token validation and user info extraction
    - Automatic provider discovery
    """

    def __init__(self):
        self.providers = {}
        self.active_states = {}  # In production, use Redis
        self.jwks_manager = JWKSManager()

        # Initialize enabled providers
        self._initialize_providers()

        logger.info(
            f"OAuthManager initialized with providers: {list(self.providers.keys())}"
        )

    def _initialize_providers(self):
        """Initialize OAuth providers based on configuration."""
        if config.is_google_oauth_enabled:
            self.providers["google"] = GoogleProvider()

        if config.is_azure_oauth_enabled:
            self.providers["azure"] = AzureProvider()

    def get_available_providers(self) -> List[str]:
        """Get list of available OAuth providers."""
        return list(self.providers.keys())

    def is_provider_enabled(self, provider_name: str) -> bool:
        """Check if OAuth provider is enabled."""
        return provider_name in self.providers

    async def get_authorization_url(
        self,
        provider_name: str,
        redirect_uri: str,
        scopes: Optional[List[str]] = None,
        state: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Get OAuth authorization URL for provider.

        Args:
            provider_name: OAuth provider name
            redirect_uri: Callback URL
            scopes: Requested scopes
            state: Optional state parameter

        Returns:
            Authorization URL and state

        Raises:
            OAuthError: Provider not found or configuration error
        """
        if provider_name not in self.providers:
            raise OAuthError(f"Provider not found: {provider_name}")

        provider = self.providers[provider_name]

        # Generate state for CSRF protection
        if not state:
            state = self._generate_state()

        # Store state with expiration
        self.active_states[state] = {
            "provider": provider_name,
            "redirect_uri": redirect_uri,
            "timestamp": time.time(),
            "expires_at": time.time() + 600,  # 10 minutes
        }

        # Get authorization URL from provider
        auth_url = await provider.get_authorization_url(
            redirect_uri=redirect_uri, scopes=scopes, state=state
        )

        logger.info(f"Generated OAuth URL for {provider_name}")

        return {
            "authorization_url": auth_url,
            "state": state,
            "provider": provider_name,
        }

    async def handle_callback(
        self, provider_name: str, code: str, state: str, redirect_uri: str
    ) -> Dict[str, Any]:
        """
        Handle OAuth callback and exchange code for tokens.

        Args:
            provider_name: OAuth provider name
            code: Authorization code
            state: State parameter
            redirect_uri: Callback URL

        Returns:
            User information and tokens

        Raises:
            InvalidStateError: Invalid or expired state
            OAuthError: Token exchange or validation error
        """
        # Validate state
        if not self._validate_state(state, provider_name):
            raise InvalidStateError("Invalid or expired state parameter")

        if provider_name not in self.providers:
            raise OAuthError(f"Provider not found: {provider_name}")

        provider = self.providers[provider_name]

        try:
            # Exchange code for tokens
            token_response = await provider.exchange_code_for_tokens(
                code=code, redirect_uri=redirect_uri, state=state
            )

            # Validate and decode ID token if present
            user_info = {}
            if "id_token" in token_response:
                user_info = await self._validate_id_token(
                    token_response["id_token"], provider
                )

            # Get additional user info if needed
            if "access_token" in token_response and not user_info:
                user_info = await provider.get_user_info(token_response["access_token"])

            # Clean up state
            self.active_states.pop(state, None)

            logger.info(
                f"OAuth callback successful for {provider_name}: {user_info.get('email', 'unknown')}"
            )

            return {
                "provider": provider_name,
                "user_info": user_info,
                "tokens": token_response,
            }

        except Exception as e:
            logger.error(f"OAuth callback failed for {provider_name}: {str(e)}")
            # Clean up state on error
            self.active_states.pop(state, None)
            raise OAuthError(f"OAuth callback failed: {str(e)}")

    async def refresh_token(
        self, provider_name: str, refresh_token: str
    ) -> Dict[str, Any]:
        """
        Refresh OAuth access token.

        Args:
            provider_name: OAuth provider name
            refresh_token: Refresh token

        Returns:
            New token response
        """
        if provider_name not in self.providers:
            raise OAuthError(f"Provider not found: {provider_name}")

        provider = self.providers[provider_name]

        try:
            return await provider.refresh_access_token(refresh_token)
        except Exception as e:
            logger.error(f"Token refresh failed for {provider_name}: {str(e)}")
            raise OAuthError(f"Token refresh failed: {str(e)}")

    async def revoke_token(
        self, provider_name: str, token: str, token_type: str = "access_token"
    ) -> bool:
        """
        Revoke OAuth token.

        Args:
            provider_name: OAuth provider name
            token: Token to revoke
            token_type: Type of token (access_token, refresh_token)

        Returns:
            True if successfully revoked
        """
        if provider_name not in self.providers:
            return False

        provider = self.providers[provider_name]

        try:
            return await provider.revoke_token(token, token_type)
        except Exception as e:
            logger.error(f"Token revocation failed for {provider_name}: {str(e)}")
            return False

    async def _validate_id_token(self, id_token: str, provider) -> Dict[str, Any]:
        """
        Validate ID token using provider's JWKS.

        Args:
            id_token: JWT ID token
            provider: OAuth provider instance

        Returns:
            Decoded token payload
        """
        jwks_url = provider.get_jwks_url()
        audience = provider.get_client_id()
        issuer = provider.get_issuer()

        return await self.jwks_manager.verify_external_token(
            token=id_token, jwks_url=jwks_url, audience=audience, issuer=issuer
        )

    def _generate_state(self) -> str:
        """Generate cryptographically secure state parameter."""
        return secrets.token_urlsafe(32)

    def _validate_state(self, state: str, provider_name: str) -> bool:
        """
        Validate state parameter.

        Args:
            state: State parameter to validate
            provider_name: Expected provider name

        Returns:
            True if state is valid
        """
        state_data = self.active_states.get(state)

        if not state_data:
            logger.warning(f"State not found: {state}")
            return False

        # Check expiration
        if time.time() > state_data["expires_at"]:
            logger.warning(f"State expired: {state}")
            self.active_states.pop(state, None)
            return False

        # Check provider match
        if state_data["provider"] != provider_name:
            logger.warning(f"Provider mismatch for state: {state}")
            return False

        return True

    def cleanup_expired_states(self):
        """Clean up expired state parameters."""
        current_time = time.time()
        expired_states = [
            state
            for state, data in self.active_states.items()
            if current_time > data["expires_at"]
        ]

        for state in expired_states:
            self.active_states.pop(state, None)

        if expired_states:
            logger.info(f"Cleaned up {len(expired_states)} expired OAuth states")
