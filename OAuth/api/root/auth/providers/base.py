"""
Abstract base OAuth provider with common functionality.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import httpx
from root.auth.exceptions.auth_exceptions import ProviderError, ValidationError
import logging

# Configure logging
logger = logging.getLogger(__name__)


class BaseOAuthProvider(ABC):
    """
    Abstract base class for OAuth providers with common functionality.

    Defines the interface that all OAuth providers must implement
    and provides shared utility methods for HTTP requests, token validation,
    and user data mapping.
    """

    async def _make_request_async(
        self, method: str, url: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Make async HTTP request with error handling.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL
            **kwargs: Additional request parameters (headers, data, etc.)

        Returns:
            Response JSON data

        Raises:
            ValidationError: If method or URL is invalid
            ProviderError: If request fails
        """
        if not isinstance(method, str) or not method.strip():
            logger.error("Invalid HTTP method provided")
            raise ValidationError("HTTP method must be a non-empty string")
        if not isinstance(url, str) or not url.strip():
            logger.error("Invalid URL provided")
            raise ValidationError("URL must be a non-empty string")
        try:
            async with httpx.AsyncClient() as client:
                response = await client.request(method, url, **kwargs)
                response.raise_for_status()
                logger.debug(f"Async request successful: {method} {url}")
                return response.json()
        except httpx.HTTPStatusError as e:
            logger.error(
                f"HTTP request failed for {method} {url}: {str(e)}", exc_info=True
            )
            raise ProviderError(
                f"HTTP request failed: {str(e)}", self.provider_name
            ) from e
        except httpx.RequestError as e:
            logger.error(f"Network error for {method} {url}: {str(e)}", exc_info=True)
            raise ProviderError(f"Network error: {str(e)}", self.provider_name) from e
        except Exception as e:
            logger.error(
                f"Unexpected error for {method} {url}: {str(e)}", exc_info=True
            )
            raise ProviderError(
                f"Unexpected request error: {str(e)}", self.provider_name
            ) from e

    def _make_request(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        """
        Make synchronous HTTP request with error handling.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL
            **kwargs: Additional request parameters (headers, data, etc.)

        Returns:
            Response JSON data

        Raises:
            ValidationError: If method or URL is invalid
            ProviderError: If request fails
        """
        if not isinstance(method, str) or not method.strip():
            logger.error("Invalid HTTP method provided")
            raise ValidationError("HTTP method must be a non-empty string")
        if not isinstance(url, str) or not url.strip():
            logger.error("Invalid URL provided")
            raise ValidationError("URL must be a non-empty string")
        try:
            with httpx.Client() as client:
                response = client.request(method, url, **kwargs)
                response.raise_for_status()
                logger.debug(f"Sync request successful: {method} {url}")
                return response.json()
        except httpx.HTTPStatusError as e:
            logger.error(
                f"HTTP request failed for {method} {url}: {str(e)}", exc_info=True
            )
            raise ProviderError(
                f"HTTP request failed: {str(e)}", self.provider_name
            ) from e
        except httpx.RequestError as e:
            logger.error(f"Network error for {method} {url}: {str(e)}", exc_info=True)
            raise ProviderError(f"Network error: {str(e)}", self.provider_name) from e
        except Exception as e:
            logger.error(
                f"Unexpected error for {method} {url}: {str(e)}", exc_info=True
            )
            raise ProviderError(
                f"Unexpected request error: {str(e)}", self.provider_name
            ) from e

    def _map_user_data(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Map provider-specific user data to standard format.
        Override in child classes for provider-specific mapping.

        Args:
            raw_data: Raw user data from provider

        Returns:
            Standardized user data with keys: id, email, first_name, last_name, name

        Raises:
            ValidationError: If raw_data is invalid or missing required fields
        """
        if not isinstance(raw_data, dict):
            logger.error("Invalid raw user data type provided")
            raise ValidationError("Raw user data must be a dictionary")
        if not raw_data.get("id"):
            logger.error("User ID missing from provider data")
            raise ValidationError("User ID is missing from provider data")

        mapped_data = {
            "id": raw_data.get("id"),
            "email": raw_data.get("email", ""),
            "first_name": raw_data.get("first_name", ""),
            "last_name": raw_data.get("last_name", ""),
            "name": raw_data.get("name", ""),
        }
        # Log missing optional fields for debugging
        optional_fields = ["email", "first_name", "last_name", "name"]
        missing_fields = [field for field in optional_fields if not raw_data.get(field)]
        if missing_fields:
            logger.debug(
                f"Missing optional fields in user data: {', '.join(missing_fields)}"
            )
        return {k: v for k, v in mapped_data.items() if v is not None}

    def _validate_token_response(self, token_data: Dict[str, Any]) -> None:
        """
        Validate token response from provider.

        Args:
            token_data: Token response data

        Raises:
            ValidationError: If token_data is invalid
            ProviderError: If token response contains errors or is missing required fields
        """
        if not isinstance(token_data, dict):
            logger.error("Invalid token response format")
            raise ValidationError("Token response must be a dictionary")
        if not token_data:
            logger.error("Empty token response received")
            raise ProviderError("Empty token response", self.provider_name)
        if "error" in token_data:
            error_desc = token_data.get("error_description", "Unknown error")
            logger.error(f"Token error from {self.provider_name}: {error_desc}")
            raise ProviderError(f"Token error: {error_desc}", self.provider_name)
        if not token_data.get("access_token"):
            logger.error(f"No access token in response from {self.provider_name}")
            raise ProviderError("No access token in response", self.provider_name)

    def _build_auth_params(
        self, base_params: Dict[str, Any], state: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Build authorization URL parameters.

        Args:
            base_params: Base parameters for the provider
            state: Optional state parameter for CSRF protection

        Returns:
            Complete parameters dict

        Raises:
            ValidationError: If base_params or state is invalid
        """
        if not isinstance(base_params, dict):
            logger.error("Invalid base parameters type provided")
            raise ValidationError("Base parameters must be a dictionary")
        params = base_params.copy()
        if state:
            if not isinstance(state, str) or not state.strip():
                logger.error("Invalid state parameter provided")
                raise ValidationError("State must be a non-empty string")
            params["state"] = state
        logger.debug(f"Built auth params: {list(params.keys())}")
        return params

    @abstractmethod
    def get_auth_url(self, state: Optional[str] = None) -> str:
        """
        Get OAuth authorization URL.

        Args:
            state: Optional state parameter for CSRF protection

        Returns:
            Authorization URL as a string

        Raises:
            ValidationError: If state is invalid
            ProviderError: If URL generation fails
        """
        pass

    @abstractmethod
    def exchange_code(
        self, auth_code: str, state: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Exchange authorization code for tokens.

        Args:
            auth_code: Authorization code from OAuth provider
            state: Optional state parameter for validation

        Returns:
            Token response dict containing access_token, id_token, refresh_token, etc.

        Raises:
            ValidationError: If auth_code or state is invalid
            ProviderError: If token exchange fails
        """
        if not isinstance(auth_code, str) or not auth_code.strip():
            logger.error("Invalid authorization code provided")
            raise ValidationError("Authorization code must be a non-empty string")
        if state is not None and (not isinstance(state, str) or not state.strip()):
            logger.error("Invalid state parameter provided")
            raise ValidationError("State must be a non-empty string or None")
        pass

    @abstractmethod
    async def exchange_code_async(
        self, auth_code: str, state: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Exchange authorization code for tokens (async).

        Args:
            auth_code: Authorization code from OAuth provider
            state: Optional state parameter for validation

        Returns:
            Token response dict containing access_token, id_token, refresh_token, etc.

        Raises:
            ValidationError: If auth_code or state is invalid
            ProviderError: If token exchange fails
        """
        if not isinstance(auth_code, str) or not auth_code.strip():
            logger.error("Invalid authorization code provided")
            raise ValidationError("Authorization code must be a non-empty string")
        if state is not None and (not isinstance(state, str) or not state.strip()):
            logger.error("Invalid state parameter provided")
            raise ValidationError("State must be a non-empty string or None")
        pass

    @abstractmethod
    def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """
        Get user information from OAuth provider.

        Args:
            access_token: Access token from provider

        Returns:
            User information dictionary with keys: id, email, first_name, last_name, name

        Raises:
            ValidationError: If access_token is invalid
            ProviderError: If user info retrieval fails
        """
        if not isinstance(access_token, str) or not access_token.strip():
            logger.error("Invalid access token provided")
            raise ValidationError("Access token must be a non-empty string")
        pass

    @abstractmethod
    async def get_user_info_async(self, access_token: str) -> Dict[str, Any]:
        """
        Get user information from OAuth provider (async).

        Args:
            access_token: Access token from provider

        Returns:
            User information dictionary with keys: id, email, first_name, last_name, name

        Raises:
            ValidationError: If access_token is invalid
            ProviderError: If user info retrieval fails
        """
        if not isinstance(access_token, str) or not access_token.strip():
            logger.error("Invalid access token provided")
            raise ValidationError("Access token must be a non-empty string")
        pass

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Get the name of the OAuth provider."""
        pass
