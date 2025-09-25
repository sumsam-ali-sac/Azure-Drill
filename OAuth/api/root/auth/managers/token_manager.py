"""
Token manager for orchestrating token operations.
"""

from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from root.domain.base_mongo_manager import BaseMongoManager
from root.auth.models.token import Token, TokenType
from root.auth.repositories.token_repository import TokenRepository
from root.auth.utils.security import SecurityUtils
from root.auth.config import config
from root.auth.exceptions.auth_exceptions import InvalidTokenError, TokenExpiredError


class TokenManager(BaseMongoManager[str, Token]):
    """
    Token manager for orchestrating token operations.

    Inherits from BaseMongoManager[str, Token] and wraps TokenRepository
    for JWT token management.
    """

    def __init__(
        self, token_repository: TokenRepository, security_utils: SecurityUtils
    ):
        """Initialize with token repository and security utils."""
        super().__init__(token_repository)
        self._token_repository = token_repository
        self._security_utils = security_utils

    def generate_token(
        self,
        user_id: str,
        token_type: TokenType,
        additional_claims: Optional[Dict[str, Any]] = None,
    ) -> Token:
        """
        Generate a new JWT token.

        Args:
            user_id: ID of the user
            token_type: Type of token (access or refresh)
            additional_claims: Additional claims to include in JWT

        Returns:
            Created Token object
        """
        # Calculate expiry based on token type
        if token_type == "access":
            expiry = datetime.utcnow() + timedelta(
                minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES
            )
        else:  # refresh
            expiry = datetime.utcnow() + timedelta(
                days=config.REFRESH_TOKEN_EXPIRE_DAYS
            )

        # Prepare JWT payload
        payload = {
            "user_id": user_id,
            "token_type": token_type,
            "exp": expiry,
            "iat": datetime.utcnow(),
        }

        if additional_claims:
            payload.update(additional_claims)

        # Generate JWT token
        jwt_token = self._security_utils.encode_jwt(payload)

        # Create token record
        token = Token(user_id=user_id, token=jwt_token, type=token_type, expiry=expiry)

        return self.create(token)

    async def generate_token_async(
        self,
        user_id: str,
        token_type: TokenType,
        additional_claims: Optional[Dict[str, Any]] = None,
    ) -> Token:
        """Generate a new JWT token (async)."""
        # Calculate expiry based on token type
        if token_type == "access":
            expiry = datetime.utcnow() + timedelta(
                minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES
            )
        else:  # refresh
            expiry = datetime.utcnow() + timedelta(
                days=config.REFRESH_TOKEN_EXPIRE_DAYS
            )

        # Prepare JWT payload
        payload = {
            "user_id": user_id,
            "token_type": token_type,
            "exp": expiry,
            "iat": datetime.utcnow(),
        }

        if additional_claims:
            payload.update(additional_claims)

        # Generate JWT token
        jwt_token = self._security_utils.encode_jwt(payload)

        # Create token record
        token = Token(user_id=user_id, token=jwt_token, type=token_type, expiry=expiry)

        return await self.create_async(token)

    def validate_token(self, token_string: str) -> Dict[str, Any]:
        """
        Validate a JWT token and return its payload.

        Args:
            token_string: JWT token string

        Returns:
            Token payload dictionary

        Raises:
            InvalidTokenError: If token is invalid
            TokenExpiredError: If token is expired
        """
        # First check if token exists in database and is not revoked
        token_record = self._token_repository.find_by_token(token_string)
        if not token_record:
            raise InvalidTokenError("Token not found")

        if token_record.is_revoked:
            raise InvalidTokenError("Token has been revoked")

        if token_record.is_expired():
            raise TokenExpiredError("Token has expired")

        # Validate JWT signature and decode payload
        try:
            payload = self._security_utils.decode_jwt(token_string)
            return payload
        except Exception as e:
            raise InvalidTokenError(f"Invalid token: {str(e)}")

    async def validate_token_async(self, token_string: str) -> Dict[str, Any]:
        """Validate a JWT token and return its payload (async)."""
        # First check if token exists in database and is not revoked
        token_record = await self._token_repository.find_by_token_async(token_string)
        if not token_record:
            raise InvalidTokenError("Token not found")

        if token_record.is_revoked:
            raise InvalidTokenError("Token has been revoked")

        if token_record.is_expired():
            raise TokenExpiredError("Token has expired")

        # Validate JWT signature and decode payload
        try:
            payload = self._security_utils.decode_jwt(token_string)
            return payload
        except Exception as e:
            raise InvalidTokenError(f"Invalid token: {str(e)}")

    def revoke_token(self, token_string: str) -> bool:
        """Revoke a token."""
        return self._token_repository.revoke_token(token_string)

    async def revoke_token_async(self, token_string: str) -> bool:
        """Revoke a token (async)."""
        return await self._token_repository.revoke_token_async(token_string)

    def revoke_user_tokens(
        self, user_id: str, token_type: Optional[TokenType] = None
    ) -> int:
        """Revoke all tokens for a user."""
        return self._token_repository.revoke_user_tokens(user_id, token_type)

    async def revoke_user_tokens_async(
        self, user_id: str, token_type: Optional[TokenType] = None
    ) -> int:
        """Revoke all tokens for a user (async)."""
        return await self._token_repository.revoke_user_tokens_async(
            user_id, token_type
        )

    def get_user_tokens(
        self, user_id: str, token_type: Optional[TokenType] = None
    ) -> List[Token]:
        """Get all tokens for a user."""
        return self._token_repository.find_by_user_id(user_id, token_type)

    async def get_user_tokens_async(
        self, user_id: str, token_type: Optional[TokenType] = None
    ) -> List[Token]:
        """Get all tokens for a user (async)."""
        return await self._token_repository.find_by_user_id_async(user_id, token_type)

    def refresh_access_token(self, refresh_token_string: str) -> Token:
        """
        Generate a new access token using a refresh token.

        Args:
            refresh_token_string: Refresh token string

        Returns:
            New access token

        Raises:
            InvalidTokenError: If refresh token is invalid
            TokenExpiredError: If refresh token is expired
        """
        # Validate refresh token
        payload = self.validate_token(refresh_token_string)

        if payload.get("token_type") != "refresh":
            raise InvalidTokenError("Token is not a refresh token")

        user_id = payload.get("user_id")
        if not user_id:
            raise InvalidTokenError("Invalid token payload")

        # Generate new access token
        return self.generate_token(user_id, "access")

    async def refresh_access_token_async(self, refresh_token_string: str) -> Token:
        """Generate a new access token using a refresh token (async)."""
        # Validate refresh token
        payload = await self.validate_token_async(refresh_token_string)

        if payload.get("token_type") != "refresh":
            raise InvalidTokenError("Token is not a refresh token")

        user_id = payload.get("user_id")
        if not user_id:
            raise InvalidTokenError("Invalid token payload")

        # Generate new access token
        return await self.generate_token_async(user_id, "access")

    def cleanup_expired_tokens(self) -> int:
        """Clean up expired tokens from the database."""
        return self._token_repository.cleanup_expired_tokens()

    async def cleanup_expired_tokens_async(self) -> int:
        """Clean up expired tokens from the database (async)."""
        return await self._token_repository.cleanup_expired_tokens_async()

    def generate_token_pair(
        self, user_id: str, additional_claims: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Token]:
        """
        Generate both access and refresh tokens for a user.

        Args:
            user_id: ID of the user
            additional_claims: Additional claims to include in tokens

        Returns:
            Dictionary with 'access' and 'refresh' tokens
        """
        access_token = self.generate_token(user_id, "access", additional_claims)
        refresh_token = self.generate_token(user_id, "refresh", additional_claims)

        return {"access": access_token, "refresh": refresh_token}

    async def generate_token_pair_async(
        self, user_id: str, additional_claims: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Token]:
        """Generate both access and refresh tokens for a user (async)."""
        access_token = await self.generate_token_async(
            user_id, "access", additional_claims
        )
        refresh_token = await self.generate_token_async(
            user_id, "refresh", additional_claims
        )

        return {"access": access_token, "refresh": refresh_token}
