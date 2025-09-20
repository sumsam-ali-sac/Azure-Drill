"""
Abstract base OAuth provider with common functionality.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import requests
from auth_service.exceptions.auth_exceptions import ProviderError

class BaseOAuthProvider(ABC):
    """
    Abstract base class for OAuth providers with common functionality.
    
    Defines the interface that all OAuth providers must implement
    and provides shared utility methods.
    """
    
    def _make_request(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        """
        Make HTTP request with error handling.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL
            **kwargs: Additional request parameters
            
        Returns:
            Response JSON data
            
        Raises:
            ProviderError: If request fails
        """
        try:
            response = requests.request(method, url, **kwargs)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            raise ProviderError(f"HTTP request failed: {str(e)}", self.provider_name)
        except Exception as e:
            raise ProviderError(f"Request error: {str(e)}", self.provider_name)
    
    def _map_user_data(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Map provider-specific user data to standard format.
        Override in child classes for provider-specific mapping.
        
        Args:
            raw_data: Raw user data from provider
            
        Returns:
            Standardized user data
        """
        return {
            "id": raw_data.get("id"),
            "email": raw_data.get("email"),
            "first_name": raw_data.get("first_name"),
            "last_name": raw_data.get("last_name"),
            "name": raw_data.get("name"),
        }
    
    def _validate_token_response(self, token_data: Dict[str, Any]) -> None:
        """
        Validate token response from provider.
        
        Args:
            token_data: Token response data
            
        Raises:
            ProviderError: If token response is invalid
        """
        if not token_data.get("access_token"):
            raise ProviderError("No access token in response", self.provider_name)
        
        if "error" in token_data:
            error_desc = token_data.get("error_description", "Unknown error")
            raise ProviderError(f"Token error: {error_desc}", self.provider_name)
    
    def _build_auth_params(self, base_params: Dict[str, Any], state: Optional[str] = None) -> Dict[str, Any]:
        """
        Build authorization URL parameters.
        
        Args:
            base_params: Base parameters for the provider
            state: Optional state parameter
            
        Returns:
            Complete parameters dict
        """
        if state:
            base_params["state"] = state
        return base_params
    
    @abstractmethod
    def get_auth_url(self, state: Optional[str] = None) -> str:
        """
        Get OAuth authorization URL.
        
        Args:
            state: Optional state parameter for CSRF protection
            
        Returns:
            Authorization URL
        """
        pass
    
    @abstractmethod
    def exchange_code(self, auth_code: str, state: Optional[str] = None) -> Dict[str, Any]:
        """
        Exchange authorization code for tokens.
        
        Args:
            auth_code: Authorization code from OAuth provider
            state: Optional state parameter for validation
            
        Returns:
            Token response dict containing access_token, id_token, etc.
        """
        pass
    
    @abstractmethod
    async def exchange_code_async(self, auth_code: str, state: Optional[str] = None) -> Dict[str, Any]:
        """Exchange authorization code for tokens (async)."""
        pass
    
    @abstractmethod
    def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """
        Get user information from OAuth provider.
        
        Args:
            access_token: Access token from provider
            
        Returns:
            User information dictionary with keys: id, email, first_name, last_name
        """
        pass
    
    @abstractmethod
    async def get_user_info_async(self, access_token: str) -> Dict[str, Any]:
        """Get user information from OAuth provider (async)."""
        pass
    
    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Get the name of the OAuth provider."""
        pass
