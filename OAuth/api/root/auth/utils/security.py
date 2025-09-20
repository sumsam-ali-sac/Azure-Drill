"""
Security utilities for password hashing, JWT handling, and future OTP support.
"""

import jwt
import pyotp
import requests
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from passlib.context import CryptContext
from auth_service.config import config
from auth_service.exceptions.auth_exceptions import InvalidTokenError

class SecurityUtils:
    """
    Security utilities for authentication operations.
    
    Handles password hashing, JWT encoding/decoding, ID token verification, and future OTP functionality.
    """
    
    def __init__(self):
        """Initialize security utilities."""
        # Password hashing context using bcrypt
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        
        # JWT configuration
        self.jwt_secret = config.JWT_SECRET
        self.jwt_algorithm = config.JWT_ALGORITHM
        
        self._jwks_cache: Dict[str, Dict] = {}
        self._jwks_cache_expiry: Dict[str, datetime] = {}
    
    def hash_password(self, password: str) -> str:
        """
        Hash a password using bcrypt.
        
        Args:
            password: Plain text password
            
        Returns:
            Hashed password
        """
        return self.pwd_context.hash(password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash.
        
        Args:
            plain_password: Plain text password
            hashed_password: Hashed password
            
        Returns:
            True if password matches, False otherwise
        """
        return self.pwd_context.verify(plain_password, hashed_password)
    
    def encode_jwt(self, payload: Dict[str, Any]) -> str:
        """
        Encode a JWT token.
        
        Args:
            payload: Token payload
            
        Returns:
            JWT token string
        """
        # Convert datetime objects to timestamps
        processed_payload = {}
        for key, value in payload.items():
            if isinstance(value, datetime):
                processed_payload[key] = value.timestamp()
            else:
                processed_payload[key] = value
        
        return jwt.encode(processed_payload, self.jwt_secret, algorithm=self.jwt_algorithm)
    
    def decode_jwt(self, token: str) -> Dict[str, Any]:
        """
        Decode and validate a JWT token.
        
        Args:
            token: JWT token string
            
        Returns:
            Token payload
            
        Raises:
            InvalidTokenError: If token is invalid or expired
        """
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])
            
            # Convert timestamps back to datetime objects
            if "exp" in payload:
                payload["exp"] = datetime.fromtimestamp(payload["exp"])
            if "iat" in payload:
                payload["iat"] = datetime.fromtimestamp(payload["iat"])
            
            return payload
            
        except jwt.ExpiredSignatureError:
            raise InvalidTokenError("Token has expired")
        except jwt.InvalidTokenError as e:
            raise InvalidTokenError(f"Invalid token: {str(e)}")
        except Exception as e:
            raise InvalidTokenError(f"Token decode error: {str(e)}")
    
    def generate_secure_token(self, length: int = 32) -> str:
        """
        Generate a secure random token.
        
        Args:
            length: Token length in bytes
            
        Returns:
            Secure random token (hex encoded)
        """
        import secrets
        return secrets.token_hex(length)
    
    # Future OTP support methods
    def generate_otp_secret(self) -> str:
        """
        Generate a new OTP secret for TOTP (future functionality).
        
        Returns:
            Base32 encoded OTP secret
        """
        return pyotp.random_base32()
    
    def generate_totp_uri(self, user_email: str, otp_secret: str, issuer: Optional[str] = None) -> str:
        """
        Generate TOTP URI for QR code (future functionality).
        
        Args:
            user_email: User's email address
            otp_secret: OTP secret
            issuer: Optional issuer name
            
        Returns:
            TOTP URI for QR code generation
        """
        issuer = issuer or config.OTP_ISSUER
        totp = pyotp.TOTP(otp_secret)
        return totp.provisioning_uri(user_email, issuer_name=issuer)
    
    def verify_totp(self, otp_secret: str, otp_code: str, window: int = 1) -> bool:
        """
        Verify TOTP code (future functionality).
        
        Args:
            otp_secret: User's OTP secret
            otp_code: OTP code to verify
            window: Time window for verification (default: 1 = 30 seconds before/after)
            
        Returns:
            True if OTP is valid, False otherwise
        """
        try:
            totp = pyotp.TOTP(otp_secret)
            return totp.verify(otp_code, valid_window=window)
        except Exception:
            return False
    
    def generate_hotp_code(self, otp_secret: str, counter: int) -> str:
        """
        Generate HOTP code (future functionality).
        
        Args:
            otp_secret: OTP secret
            counter: Counter value
            
        Returns:
            6-digit HOTP code
        """
        hotp = pyotp.HOTP(otp_secret)
        return hotp.at(counter)
    
    def verify_hotp(self, otp_secret: str, otp_code: str, counter: int) -> bool:
        """
        Verify HOTP code (future functionality).
        
        Args:
            otp_secret: User's OTP secret
            otp_code: OTP code to verify
            counter: Counter value
            
        Returns:
            True if OTP is valid, False otherwise
        """
        try:
            hotp = pyotp.HOTP(otp_secret)
            return hotp.verify(otp_code, counter)
        except Exception:
            return False
    
    def constant_time_compare(self, val1: str, val2: str) -> bool:
        """
        Constant time string comparison to prevent timing attacks.
        
        Args:
            val1: First string
            val2: Second string
            
        Returns:
            True if strings are equal, False otherwise
        """
        import hmac
        return hmac.compare_digest(val1, val2)
    
    def generate_csrf_token(self) -> str:
        """
        Generate CSRF token for form protection.
        
        Returns:
            CSRF token
        """
        return self.generate_secure_token(16)
    
    def hash_api_key(self, api_key: str) -> str:
        """
        Hash API key for secure storage.
        
        Args:
            api_key: Plain API key
            
        Returns:
            Hashed API key
        """
        return self.hash_password(api_key)
    
    def verify_api_key(self, plain_api_key: str, hashed_api_key: str) -> bool:
        """
        Verify API key against its hash.
        
        Args:
            plain_api_key: Plain API key
            hashed_api_key: Hashed API key
            
        Returns:
            True if API key matches, False otherwise
        """
        return self.verify_password(plain_api_key, hashed_api_key)
    
    def verify_provider_id_token(self, id_token: str, provider_name: str) -> Dict[str, Any]:
        """
        Verify ID token from OAuth provider.
        
        Args:
            id_token: ID token JWT from provider
            provider_name: Name of the OAuth provider (google, azure)
            
        Returns:
            Verified ID token payload
            
        Raises:
            InvalidTokenError: If token verification fails
        """
        try:
            # Get provider-specific configuration
            provider_config = self._get_provider_config(provider_name)
            
            # Get provider's public keys
            public_key = self._get_provider_public_key(id_token, provider_config)
            
            # Verify and decode the ID token
            payload = jwt.decode(
                id_token,
                public_key,
                algorithms=['RS256'],
                audience=provider_config['audience'],
                issuer=provider_config['issuer']
            )
            
            # Additional validation
            self._validate_id_token_claims(payload, provider_name)
            
            return payload
            
        except jwt.InvalidTokenError as e:
            raise InvalidTokenError(f"Invalid ID token from {provider_name}: {str(e)}")
        except Exception as e:
            raise InvalidTokenError(f"ID token verification failed for {provider_name}: {str(e)}")
    
    def _get_provider_config(self, provider_name: str) -> Dict[str, str]:
        """Get provider-specific configuration for ID token verification."""
        if provider_name.lower() == 'google':
            return {
                'jwks_url': 'https://www.googleapis.com/oauth2/v3/certs',
                'issuer': 'https://accounts.google.com',
                'audience': config.GOOGLE_CLIENT_ID
            }
        elif provider_name.lower() == 'azure':
            tenant_id = config.AZURE_TENANT_ID or 'common'
            return {
                'jwks_url': f'https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys',
                'issuer': f'https://login.microsoftonline.com/{tenant_id}/v2.0',
                'audience': config.AZURE_CLIENT_ID
            }
        else:
            raise InvalidTokenError(f'Unsupported provider for ID token verification: {provider_name}')
    
    def _get_provider_public_key(self, id_token: str, provider_config: Dict[str, str]):
        """Get provider's public key for token verification with caching."""
        jwks_url = provider_config['jwks_url']
        
        # Check cache first
        if (jwks_url in self._jwks_cache and 
            jwks_url in self._jwks_cache_expiry and 
            datetime.now() < self._jwks_cache_expiry[jwks_url]):
            jwks = self._jwks_cache[jwks_url]
        else:
            # Fetch fresh JWKS
            response = requests.get(jwks_url, timeout=10)
            response.raise_for_status()
            jwks = response.json()
            
            # Cache for 1 hour
            self._jwks_cache[jwks_url] = jwks
            self._jwks_cache_expiry[jwks_url] = datetime.now() + timedelta(hours=1)
        
        # Get token header to find the right key
        header = jwt.get_unverified_header(id_token)
        kid = header.get('kid')
        
        if not kid:
            raise InvalidTokenError("ID token missing 'kid' in header")
        
        # Find the matching key
        for key in jwks.get('keys', []):
            if key.get('kid') == kid:
                return jwt.algorithms.RSAAlgorithm.from_jwk(key)
        
        raise InvalidTokenError(f"Unable to find matching key for kid: {kid}")
    
    def _validate_id_token_claims(self, payload: Dict[str, Any], provider_name: str):
        """Validate additional ID token claims."""
        # Check token expiration (jwt.decode already handles this, but double-check)
        exp = payload.get('exp')
        if exp and datetime.fromtimestamp(exp) < datetime.now():
            raise InvalidTokenError("ID token has expired")
        
        # Check issued at time (not too far in the future)
        iat = payload.get('iat')
        if iat and datetime.fromtimestamp(iat) > datetime.now() + timedelta(minutes=5):
            raise InvalidTokenError("ID token issued in the future")
        
        # Provider-specific validations
        if provider_name.lower() == 'google':
            # Google-specific checks
            if not payload.get('email_verified', False):
                # Note: This might be too strict for some use cases
                pass  # Could add warning or optional strict mode
        
        elif provider_name.lower() == 'azure':
            # Azure-specific checks
            if config.AZURE_TENANT_ID and config.AZURE_TENANT_ID != 'common':
                tid = payload.get('tid')
                if tid != config.AZURE_TENANT_ID:
                    raise InvalidTokenError(f"ID token from wrong tenant: {tid}")
