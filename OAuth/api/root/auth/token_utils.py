"""
JWT token utilities for creation, verification, and management.
Supports HS256, RS256, and ES256 algorithms with comprehensive validation.
"""

import jwt
import json
import requests
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, Union, List
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from .configs import config
from .secrets import secret_manager
from .constants import (
    TOKEN_TYPE_ACCESS,
    TOKEN_TYPE_REFRESH,
    TOKEN_TYPE_RESET,
    ALLOWED_JWT_ALGORITHMS
)
from .exceptions import (
    TokenExpiredError,
    TokenInvalidError,
    AuthConfigurationError
)


class TokenManager:
    """Manages JWT token operations with support for multiple algorithms."""
    
    def __init__(self):
        self._jwks_cache: Dict[str, Dict] = {}
        self._jwks_cache_expiry: Dict[str, datetime] = {}
    
    def create_token(
        self,
        payload: Dict[str, Any],
        expires_minutes: Optional[int] = None,
        token_type: str = TOKEN_TYPE_ACCESS,
        algorithm: Optional[str] = None
    ) -> str:
        """
        Create a JWT token with the specified payload and expiration.
        
        Args:
            payload: Token payload data
            expires_minutes: Token expiration in minutes
            token_type: Type of token (access, refresh, reset)
            algorithm: JWT algorithm to use (defaults to config)
        
        Returns:
            Encoded JWT token string
        """
        algorithm = algorithm or config.JWT_ALGORITHM
        
        if algorithm not in ALLOWED_JWT_ALGORITHMS:
            raise AuthConfigurationError(f"Unsupported JWT algorithm: {algorithm}")
        
        # Set default expiration based on token type
        if expires_minutes is None:
            if token_type == TOKEN_TYPE_REFRESH:
                expires_minutes = config.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60
            elif token_type == TOKEN_TYPE_RESET:
                expires_minutes = 15  # 15 minutes for password reset
            else:
                expires_minutes = config.ACCESS_TOKEN_EXPIRE_MINUTES
        
        # Prepare token payload
        now = datetime.now(timezone.utc)
        token_payload = {
            **payload,
            "iat": now,
            "exp": now + timedelta(minutes=expires_minutes),
            "type": token_type,
            "alg": algorithm
        }
        
        # Get signing key based on algorithm
        if algorithm == "HS256":
            key = secret_manager.get_jwt_secret()
        elif algorithm in ["RS256", "ES256"]:
            key = secret_manager.get_private_key()
        else:
            raise AuthConfigurationError(f"Unsupported algorithm: {algorithm}")
        
        try:
            return jwt.encode(token_payload, key, algorithm=algorithm)
        except Exception as e:
            raise TokenInvalidError(f"Failed to create token: {str(e)}")
    
    def verify_token(
        self,
        token: str,
        token_type: Optional[str] = None,
        jwks_url: Optional[str] = None,
        audience: Optional[str] = None,
        issuer: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Verify and decode a JWT token.
        
        Args:
            token: JWT token to verify
            token_type: Expected token type
            jwks_url: JWKS URL for key verification (for external tokens)
            audience: Expected audience
            issuer: Expected issuer
        
        Returns:
            Decoded token payload
        """
        try:
            # Decode header to get algorithm and key ID
            header = jwt.get_unverified_header(token)
            algorithm = header.get("alg")
            key_id = header.get("kid")
            
            if algorithm not in ALLOWED_JWT_ALGORITHMS:
                raise TokenInvalidError(f"Unsupported algorithm: {algorithm}")
            
            # Get verification key
            if jwks_url:
                # External token verification (e.g., from OAuth providers)
                key = self._get_jwks_key(jwks_url, key_id)
            else:
                # Internal token verification
                if algorithm == "HS256":
                    key = secret_manager.get_jwt_secret()
                elif algorithm in ["RS256", "ES256"]:
                    key = secret_manager.get_public_key()
                else:
                    raise AuthConfigurationError(f"Unsupported algorithm: {algorithm}")
            
            # Verify and decode token
            payload = jwt.decode(
                token,
                key,
                algorithms=[algorithm],
                audience=audience,
                issuer=issuer,
                options={
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_signature": True
                }
            )
            
            # Verify token type if specified
            if token_type and payload.get("type") != token_type:
                raise TokenInvalidError(f"Invalid token type. Expected: {token_type}")
            
            return payload
            
        except jwt.ExpiredSignatureError:
            raise TokenExpiredError("Token has expired")
        except jwt.InvalidTokenError as e:
            raise TokenInvalidError(f"Invalid token: {str(e)}")
        except Exception as e:
            raise TokenInvalidError(f"Token verification failed: {str(e)}")
    
    def refresh_access_token(self, refresh_token: str) -> str:
        """
        Create a new access token from a valid refresh token.
        
        Args:
            refresh_token: Valid refresh token
        
        Returns:
            New access token
        """
        try:
            # Verify refresh token
            payload = self.verify_token(refresh_token, token_type=TOKEN_TYPE_REFRESH)
            
            # Create new access token with same user data
            access_payload = {
                "sub": payload.get("sub"),
                "email": payload.get("email"),
                "roles": payload.get("roles", []),
                "permissions": payload.get("permissions", [])
            }
            
            return self.create_token(
                access_payload,
                expires_minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES,
                token_type=TOKEN_TYPE_ACCESS
            )
            
        except (TokenExpiredError, TokenInvalidError):
            raise TokenInvalidError("Invalid or expired refresh token")
    
    def create_password_reset_token(self, email: str) -> str:
        """
        Create a password reset token.
        
        Args:
            email: User email address
        
        Returns:
            Password reset token
        """
        payload = {
            "sub": email,
            "email": email,
            "action": "password_reset"
        }
        
        return self.create_token(
            payload,
            expires_minutes=15,  # 15 minutes expiry
            token_type=TOKEN_TYPE_RESET
        )
    
    def verify_password_reset_token(self, token: str) -> str:
        """
        Verify password reset token and return email.
        
        Args:
            token: Password reset token
        
        Returns:
            User email from token
        """
        payload = self.verify_token(token, token_type=TOKEN_TYPE_RESET)
        
        if payload.get("action") != "password_reset":
            raise TokenInvalidError("Invalid password reset token")
        
        return payload.get("email")
    
    def decode_token_without_verification(self, token: str) -> Dict[str, Any]:
        """
        Decode token without verification (for debugging/inspection).
        
        Args:
            token: JWT token to decode
        
        Returns:
            Decoded token payload
        """
        try:
            return jwt.decode(token, options={"verify_signature": False})
        except Exception as e:
            raise TokenInvalidError(f"Failed to decode token: {str(e)}")
    
    def get_token_expiry(self, token: str) -> Optional[datetime]:
        """
        Get token expiration time.
        
        Args:
            token: JWT token
        
        Returns:
            Token expiration datetime
        """
        try:
            payload = self.decode_token_without_verification(token)
            exp = payload.get("exp")
            if exp:
                return datetime.fromtimestamp(exp, tz=timezone.utc)
            return None
        except Exception:
            return None
    
    def is_token_expired(self, token: str) -> bool:
        """
        Check if token is expired.
        
        Args:
            token: JWT token
        
        Returns:
            True if token is expired
        """
        expiry = self.get_token_expiry(token)
        if expiry:
            return datetime.now(timezone.utc) > expiry
        return True
    
    def _get_jwks_key(self, jwks_url: str, key_id: Optional[str] = None) -> Union[str, rsa.RSAPublicKey, ec.EllipticCurvePublicKey]:
        """
        Get public key from JWKS endpoint.
        
        Args:
            jwks_url: JWKS endpoint URL
            key_id: Key ID to retrieve
        
        Returns:
            Public key for token verification
        """
        # Check cache first
        cache_key = f"{jwks_url}:{key_id or 'default'}"
        now = datetime.now(timezone.utc)
        
        if (cache_key in self._jwks_cache and 
            cache_key in self._jwks_cache_expiry and
            now < self._jwks_cache_expiry[cache_key]):
            return self._jwks_cache[cache_key]
        
        try:
            # Fetch JWKS
            response = requests.get(jwks_url, timeout=10)
            response.raise_for_status()
            jwks = response.json()
            
            # Find the right key
            keys = jwks.get("keys", [])
            if not keys:
                raise TokenInvalidError("No keys found in JWKS")
            
            # Select key by ID or use first available
            selected_key = None
            if key_id:
                selected_key = next((k for k in keys if k.get("kid") == key_id), None)
            else:
                selected_key = keys[0]
            
            if not selected_key:
                raise TokenInvalidError(f"Key not found in JWKS: {key_id}")
            
            # Convert JWK to public key
            key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(selected_key))
            
            # Cache the key (expire in 1 hour)
            self._jwks_cache[cache_key] = key
            self._jwks_cache_expiry[cache_key] = now + timedelta(hours=1)
            
            return key
            
        except requests.RequestException as e:
            raise TokenInvalidError(f"Failed to fetch JWKS: {str(e)}")
        except Exception as e:
            raise TokenInvalidError(f"Failed to process JWKS: {str(e)}")
    
    def create_token_pair(self, payload: Dict[str, Any]) -> Dict[str, str]:
        """
        Create both access and refresh tokens.
        
        Args:
            payload: Token payload data
        
        Returns:
            Dictionary with access_token and refresh_token
        """
        access_token = self.create_token(
            payload,
            expires_minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES,
            token_type=TOKEN_TYPE_ACCESS
        )
        
        refresh_token = self.create_token(
            payload,
            expires_minutes=config.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60,
            token_type=TOKEN_TYPE_REFRESH
        )
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token
        }
    
    def revoke_token(self, token: str) -> bool:
        """
        Revoke a token (add to blacklist).
        Note: This is a placeholder for token blacklisting implementation.
        In production, you would store revoked tokens in a cache/database.
        
        Args:
            token: Token to revoke
        
        Returns:
            True if token was revoked successfully
        """
        # TODO: Implement token blacklisting with Redis/database
        # For now, this is a placeholder
        return True
    
    def is_token_revoked(self, token: str) -> bool:
        """
        Check if token is revoked.
        Note: This is a placeholder for token blacklist checking.
        
        Args:
            token: Token to check
        
        Returns:
            True if token is revoked
        """
        # TODO: Implement token blacklist checking
        # For now, this is a placeholder
        return False


# Global token manager instance
token_manager = TokenManager()

# Convenience functions for backward compatibility
def create_token(payload: Dict[str, Any], expires_minutes: Optional[int] = None) -> str:
    """Create a JWT token."""
    return token_manager.create_token(payload, expires_minutes)

def verify_token(token: str, jwks_url: Optional[str] = None) -> Dict[str, Any]:
    """Verify a JWT token."""
    return token_manager.verify_token(token, jwks_url=jwks_url)

def refresh_access_token(refresh_token: str) -> str:
    """Refresh an access token."""
    return token_manager.refresh_access_token(refresh_token)
