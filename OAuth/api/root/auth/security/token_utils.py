"""
Advanced JWT token management with support for multiple algorithms.
Handles token creation, verification, refresh, and key management.
"""

import jwt
import json
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Union
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
import logging

from auth.configs import config
from auth.constants import ALLOWED_JWT_ALGORITHMS, TOKEN_TYPE_BEARER
from auth.exceptions import TokenExpiredError, InvalidTokenError
from auth.secrets import SecretsManager

logger = logging.getLogger(__name__)


class TokenManager:
    """
    Advanced JWT token management with multi-algorithm support.
    
    Features:
    - HS256, RS256, ES256 algorithm support
    - Automatic key rotation
    - Token blacklisting
    - Refresh token management
    - Custom claims validation
    """
    
    def __init__(self):
        self.secrets_manager = SecretsManager()
        self.algorithm = config.JWT_ALGORITHM
        self.blacklisted_tokens = set()  # In production, use Redis
        
        # Validate algorithm
        if self.algorithm not in ALLOWED_JWT_ALGORITHMS:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")
        
        logger.info(f"TokenManager initialized with {self.algorithm}")
    
    def create_token(
        self, 
        payload: Dict[str, Any], 
        expires_minutes: int,
        token_type: str = "access"
    ) -> str:
        """
        Create JWT token with specified payload and expiration.
        
        Args:
            payload: Token payload/claims
            expires_minutes: Expiration time in minutes
            token_type: Type of token (access, refresh, etc.)
            
        Returns:
            Encoded JWT token
        """
        now = datetime.utcnow()
        
        # Standard claims
        claims = {
            "iat": now,
            "exp": now + timedelta(minutes=expires_minutes),
            "nbf": now,
            "jti": self._generate_jti(),
            "type": token_type,
            **payload
        }
        
        # Get signing key
        key = self._get_signing_key()
        
        try:
            token = jwt.encode(claims, key, algorithm=self.algorithm)
            logger.debug(f"Created {token_type} token for subject: {payload.get('sub', 'unknown')}")
            return token
            
        except Exception as e:
            logger.error(f"Token creation failed: {str(e)}")
            raise InvalidTokenError("Failed to create token")
    
    def verify_token(
        self, 
        token: str, 
        verify_exp: bool = True,
        verify_signature: bool = True,
        audience: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Verify and decode JWT token.
        
        Args:
            token: JWT token to verify
            verify_exp: Verify expiration
            verify_signature: Verify signature
            audience: Expected audience
            
        Returns:
            Decoded token payload
            
        Raises:
            TokenExpiredError: Token has expired
            InvalidTokenError: Token is invalid
        """
        if not token:
            raise InvalidTokenError("Token is required")
        
        # Check blacklist
        if self._is_blacklisted(token):
            raise InvalidTokenError("Token has been revoked")
        
        try:
            # Get verification key
            key = self._get_verification_key()
            
            # Decode options
            options = {
                "verify_signature": verify_signature,
                "verify_exp": verify_exp,
                "verify_nbf": True,
                "verify_iat": True,
                "verify_aud": audience is not None
            }
            
            payload = jwt.decode(
                token,
                key,
                algorithms=[self.algorithm],
                options=options,
                audience=audience
            )
            
            logger.debug(f"Token verified for subject: {payload.get('sub', 'unknown')}")
            return payload
            
        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
            raise TokenExpiredError("Token has expired")
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {str(e)}")
            raise InvalidTokenError(f"Invalid token: {str(e)}")
        except Exception as e:
            logger.error(f"Token verification failed: {str(e)}")
            raise InvalidTokenError("Token verification failed")
    
    def refresh_access_token(self, refresh_token: str) -> str:
        """
        Create new access token from refresh token.
        
        Args:
            refresh_token: Valid refresh token
            
        Returns:
            New access token
        """
        # Verify refresh token
        payload = self.verify_token(refresh_token)
        
        if payload.get("type") != "refresh":
            raise InvalidTokenError("Invalid refresh token type")
        
        # Create new access token with updated claims
        access_payload = {
            "sub": payload["sub"],
            "user_id": payload.get("user_id"),
            "roles": payload.get("roles", []),
            "permissions": payload.get("permissions", [])
        }
        
        return self.create_token(
            access_payload,
            config.ACCESS_TOKEN_EXPIRE_MINUTES,
            "access"
        )
    
    def revoke_token(self, token: str) -> bool:
        """
        Revoke/blacklist a token.
        
        Args:
            token: Token to revoke
            
        Returns:
            True if successfully revoked
        """
        try:
            # Decode to get JTI
            payload = jwt.decode(token, options={"verify_signature": False})
            jti = payload.get("jti")
            
            if jti:
                self.blacklisted_tokens.add(jti)
                logger.info(f"Token revoked: {jti}")
                return True
                
        except Exception as e:
            logger.error(f"Token revocation failed: {str(e)}")
        
        return False
    
    def decode_token_unsafe(self, token: str) -> Dict[str, Any]:
        """
        Decode token without verification (for debugging/inspection).
        
        Args:
            token: JWT token
            
        Returns:
            Decoded payload
        """
        try:
            return jwt.decode(token, options={"verify_signature": False})
        except Exception as e:
            logger.error(f"Unsafe token decode failed: {str(e)}")
            return {}
    
    def get_token_info(self, token: str) -> Dict[str, Any]:
        """
        Get token information without full verification.
        
        Args:
            token: JWT token
            
        Returns:
            Token information
        """
        try:
            header = jwt.get_unverified_header(token)
            payload = self.decode_token_unsafe(token)
            
            return {
                "header": header,
                "payload": payload,
                "is_expired": self._is_expired(payload),
                "time_to_expiry": self._time_to_expiry(payload)
            }
            
        except Exception as e:
            logger.error(f"Token info extraction failed: {str(e)}")
            return {}
    
    def _get_signing_key(self) -> Union[str, bytes]:
        """Get key for token signing based on algorithm."""
        if self.algorithm == "HS256":
            return self.secrets_manager.get_jwt_secret()
        elif self.algorithm in ["RS256", "ES256"]:
            private_key = self.secrets_manager.get_private_key()
            if isinstance(private_key, str):
                return private_key.encode()
            return private_key
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")
    
    def _get_verification_key(self) -> Union[str, bytes]:
        """Get key for token verification based on algorithm."""
        if self.algorithm == "HS256":
            return self.secrets_manager.get_jwt_secret()
        elif self.algorithm in ["RS256", "ES256"]:
            public_key = self.secrets_manager.get_public_key()
            if isinstance(public_key, str):
                return public_key.encode()
            return public_key
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")
    
    def _generate_jti(self) -> str:
        """Generate unique token ID."""
        import uuid
        return str(uuid.uuid4())
    
    def _is_blacklisted(self, token: str) -> bool:
        """Check if token is blacklisted."""
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            jti = payload.get("jti")
            return jti in self.blacklisted_tokens
        except:
            return False
    
    def _is_expired(self, payload: Dict[str, Any]) -> bool:
        """Check if token payload indicates expiration."""
        exp = payload.get("exp")
        if exp:
            return datetime.utcnow().timestamp() > exp
        return False
    
    def _time_to_expiry(self, payload: Dict[str, Any]) -> Optional[int]:
        """Get seconds until token expires."""
        exp = payload.get("exp")
        if exp:
            remaining = exp - datetime.utcnow().timestamp()
            return max(0, int(remaining))
        return None


class JWKSManager:
    """
    JSON Web Key Set (JWKS) management for external token verification.
    Used for verifying tokens from OAuth providers.
    """
    
    def __init__(self):
        self.jwks_cache = {}
        self.cache_ttl = 3600  # 1 hour
        logger.info("JWKSManager initialized")
    
    async def get_jwks(self, jwks_url: str) -> Dict[str, Any]:
        """
        Fetch JWKS from URL with caching.
        
        Args:
            jwks_url: JWKS endpoint URL
            
        Returns:
            JWKS data
        """
        import aiohttp
        
        # Check cache
        cached = self.jwks_cache.get(jwks_url)
        if cached and time.time() - cached["timestamp"] < self.cache_ttl:
            return cached["data"]
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(jwks_url, timeout=10) as response:
                    if response.status == 200:
                        jwks_data = await response.json()
                        
                        # Cache the result
                        self.jwks_cache[jwks_url] = {
                            "data": jwks_data,
                            "timestamp": time.time()
                        }
                        
                        logger.info(f"JWKS fetched from: {jwks_url}")
                        return jwks_data
                    else:
                        raise Exception(f"HTTP {response.status}")
                        
        except Exception as e:
            logger.error(f"JWKS fetch failed for {jwks_url}: {str(e)}")
            raise InvalidTokenError(f"Failed to fetch JWKS: {str(e)}")
    
    async def verify_external_token(
        self, 
        token: str, 
        jwks_url: str,
        audience: Optional[str] = None,
        issuer: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Verify token using external JWKS.
        
        Args:
            token: JWT token to verify
            jwks_url: JWKS endpoint URL
            audience: Expected audience
            issuer: Expected issuer
            
        Returns:
            Decoded token payload
        """
        jwks_data = await self.get_jwks(jwks_url)
        
        try:
            # Get token header to find key ID
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            
            if not kid:
                raise InvalidTokenError("Token missing key ID")
            
            # Find matching key in JWKS
            key_data = None
            for key in jwks_data.get("keys", []):
                if key.get("kid") == kid:
                    key_data = key
                    break
            
            if not key_data:
                raise InvalidTokenError(f"Key not found in JWKS: {kid}")
            
            # Convert JWK to PEM format
            public_key = self._jwk_to_pem(key_data)
            
            # Verify token
            payload = jwt.decode(
                token,
                public_key,
                algorithms=[header.get("alg", "RS256")],
                audience=audience,
                issuer=issuer
            )
            
            logger.info(f"External token verified for: {payload.get('sub', 'unknown')}")
            return payload
            
        except jwt.InvalidTokenError as e:
            logger.warning(f"External token verification failed: {str(e)}")
            raise InvalidTokenError(f"Token verification failed: {str(e)}")
    
    def _jwk_to_pem(self, jwk_data: Dict[str, Any]) -> bytes:
        """Convert JWK to PEM format."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        import base64
        
        try:
            if jwk_data.get("kty") == "RSA":
                # RSA key
                n = self._base64url_decode(jwk_data["n"])
                e = self._base64url_decode(jwk_data["e"])
                
                public_key = rsa.RSAPublicNumbers(
                    int.from_bytes(e, byteorder="big"),
                    int.from_bytes(n, byteorder="big")
                ).public_key()
                
                return public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            else:
                raise ValueError(f"Unsupported key type: {jwk_data.get('kty')}")
                
        except Exception as e:
            logger.error(f"JWK to PEM conversion failed: {str(e)}")
            raise InvalidTokenError("Failed to convert JWK to PEM")
    
    def _base64url_decode(self, data: str) -> bytes:
        """Decode base64url string."""
        import base64
        
        # Add padding if needed
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        
        return base64.urlsafe_b64decode(data)
