"""
Security utilities for password hashing, JWT handling, and future OTP support.
"""

import jwt
import pyotp
import httpx
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from passlib.context import CryptContext
from auth.config import config
from auth.exceptions.auth_exceptions import InvalidTokenError, ValidationError
import logging

# Configure logging
logger = logging.getLogger(__name__)


class SecurityUtils:
    """
    Security utilities for authentication operations.

    Handles password hashing, JWT encoding/decoding, ID token verification, and future OTP functionality.
    """

    def __init__(self):
        """Initialize security utilities."""
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        self.jwt_secret = config.JWT_SECRET
        self.jwt_algorithm = config.JWT_ALGORITHM
        self._jwks_cache: Dict[str, Dict] = {}
        self._jwks_cache_expiry: Dict[str, datetime] = {}

        if not self.jwt_secret or not self.jwt_algorithm:
            raise ValidationError("JWT configuration is incomplete")

    def hash_password(self, password: str) -> str:
        """
        Hash a password using bcrypt.
        """
        if not isinstance(password, str) or not password:
            raise ValidationError("Password must be a non-empty string")
        return self.pwd_context.hash(password)

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash.
        """
        if not isinstance(plain_password, str) or not isinstance(hashed_password, str):
            raise ValidationError("Invalid password or hash format")
        return self.pwd_context.verify(plain_password, hashed_password)

    def encode_jwt(self, payload: Dict[str, Any]) -> str:
        """
        Encode a JWT token.
        """
        if not isinstance(payload, dict):
            raise ValidationError("Payload must be a dictionary")

        processed_payload = {}
        for key, value in payload.items():
            if isinstance(value, datetime):
                processed_payload[key] = int(value.timestamp())
            else:
                processed_payload[key] = value

        try:
            return jwt.encode(
                processed_payload, self.jwt_secret, algorithm=self.jwt_algorithm
            )
        except Exception as e:
            logger.error(f"JWT encoding failed: {str(e)}", exc_info=True)
            raise InvalidTokenError(f"JWT encoding failed: {str(e)}") from e

    def decode_jwt(self, token: str) -> Dict[str, Any]:
        """
        Decode and validate a JWT token.
        """
        if not isinstance(token, str) or not token:
            raise InvalidTokenError("Token must be a non-empty string")

        try:
            payload = jwt.decode(
                token, self.jwt_secret, algorithms=[self.jwt_algorithm]
            )

            if "exp" in payload and isinstance(payload["exp"], (int, float)):
                payload["exp"] = datetime.fromtimestamp(payload["exp"])
            if "iat" in payload and isinstance(payload["iat"], (int, float)):
                payload["iat"] = datetime.fromtimestamp(payload["iat"])

            return payload

        except jwt.ExpiredSignatureError as e:
            logger.error(f"Token expired: {str(e)}", exc_info=True)
            raise InvalidTokenError("Token has expired") from e
        except jwt.InvalidTokenError as e:
            logger.error(f"Invalid token: {str(e)}", exc_info=True)
            raise InvalidTokenError(f"Invalid token: {str(e)}") from e
        except Exception as e:
            logger.error(f"Token decode error: {str(e)}", exc_info=True)
            raise InvalidTokenError(f"Token decode error: {str(e)}") from e

    def generate_secure_token(self, length: int = 32) -> str:
        """
        Generate a secure random token.
        """
        if not isinstance(length, int) or length <= 0:
            raise ValidationError("Token length must be a positive integer")
        import secrets

        return secrets.token_hex(length)

    def generate_otp_secret(self) -> str:
        """
        Generate a new OTP secret for TOTP (future functionality).
        """
        return pyotp.random_base32()

    def generate_totp_uri(
        self, user_email: str, otp_secret: str, issuer: Optional[str] = None
    ) -> str:
        """
        Generate TOTP URI for QR code (future functionality).
        """
        if not isinstance(user_email, str) or not user_email:
            raise ValidationError("User email must be a non-empty string")
        if not isinstance(otp_secret, str) or not otp_secret:
            raise ValidationError("OTP secret must be a non-empty string")
        issuer = issuer or config.OTP_ISSUER or "AuthService"
        try:
            totp = pyotp.TOTP(otp_secret)
            return totp.provisioning_uri(user_email, issuer_name=issuer)
        except Exception as e:
            logger.error(f"Failed to generate TOTP URI: {str(e)}", exc_info=True)
            raise ValidationError(f"Failed to generate TOTP URI: {str(e)}") from e

    def verify_totp(self, otp_secret: str, otp_code: str, window: int = 1) -> bool:
        """
        Verify TOTP code (future functionality).
        """
        if not isinstance(otp_secret, str) or not isinstance(otp_code, str):
            raise ValidationError("OTP secret and code must be strings")
        try:
            totp = pyotp.TOTP(otp_secret)
            return totp.verify(otp_code, valid_window=window)
        except Exception as e:
            logger.error(f"TOTP verification failed: {str(e)}", exc_info=True)
            return False

    def generate_hotp_code(self, otp_secret: str, counter: int) -> str:
        """
        Generate HOTP code (future functionality).
        """
        if (
            not isinstance(otp_secret, str)
            or not isinstance(counter, int)
            or counter < 0
        ):
            raise ValidationError("Invalid OTP secret or counter")
        try:
            hotp = pyotp.HOTP(otp_secret)
            return hotp.at(counter)
        except Exception as e:
            logger.error(f"HOTP generation failed: {str(e)}", exc_info=True)
            raise ValidationError(f"HOTP generation failed: {str(e)}") from e

    def verify_hotp(self, otp_secret: str, otp_code: str, counter: int) -> bool:
        """
        Verify HOTP code (future functionality).
        """
        if (
            not isinstance(otp_secret, str)
            or not isinstance(otp_code, str)
            or not isinstance(counter, int)
            or counter < 0
        ):
            raise ValidationError("Invalid OTP secret, code, or counter")
        try:
            hotp = pyotp.HOTP(otp_secret)
            return hotp.verify(otp_code, counter)
        except Exception as e:
            logger.error(f"HOTP verification failed: {str(e)}", exc_info=True)
            return False

    def constant_time_compare(self, val1: str, val2: str) -> bool:
        """
        Constant time string comparison to prevent timing attacks.
        """
        if not isinstance(val1, str) or not isinstance(val2, str):
            raise ValidationError("Values must be strings")
        import hmac

        return hmac.compare_digest(val1.encode("utf-8"), val2.encode("utf-8"))

    def generate_csrf_token(self) -> str:
        """
        Generate CSRF token for form protection.
        """
        return self.generate_secure_token(16)

    def hash_api_key(self, api_key: str) -> str:
        """
        Hash API key for secure storage.
        """
        if not isinstance(api_key, str) or not api_key:
            raise ValidationError("API key must be a non-empty string")
        return self.hash_password(api_key)

    def verify_api_key(self, plain_api_key: str, hashed_api_key: str) -> bool:
        """
        Verify API key against its hash.
        """
        if not isinstance(plain_api_key, str) or not isinstance(hashed_api_key, str):
            raise ValidationError("API key and hash must be strings")
        return self.verify_password(plain_api_key, hashed_api_key)

    def verify_provider_id_token(
        self, id_token: str, provider_name: str
    ) -> Dict[str, Any]:
        """
        Verify ID token from OAuth provider.
        """
        if not isinstance(id_token, str) or not id_token:
            raise InvalidTokenError("ID token must be a non-empty string")
        if not isinstance(provider_name, str) or not provider_name:
            raise InvalidTokenError("Provider name must be a non-empty string")

        try:
            provider_config = self._get_provider_config(provider_name.lower())
            public_key = self._get_provider_public_key(id_token, provider_config)
            payload = jwt.decode(
                id_token,
                public_key,
                algorithms=["RS256"],
                audience=provider_config["audience"],
                issuer=provider_config["issuer"],
                options={"verify_exp": True, "verify_aud": True, "verify_iss": True},
            )
            self._validate_id_token_claims(payload, provider_name.lower())
            return payload
        except jwt.InvalidTokenError as e:
            logger.error(
                f"Invalid ID token from {provider_name}: {str(e)}", exc_info=True
            )
            raise InvalidTokenError(
                f"Invalid ID token from {provider_name}: {str(e)}"
            ) from e
        except Exception as e:
            logger.error(
                f"ID token verification failed for {provider_name}: {str(e)}",
                exc_info=True,
            )
            raise InvalidTokenError(
                f"ID token verification failed for {provider_name}: {str(e)}"
            ) from e

    def _get_provider_config(self, provider_name: str) -> Dict[str, str]:
        """Get provider-specific configuration for ID token verification."""
        if provider_name == "google":
            return {
                "jwks_url": "https://www.googleapis.com/oauth2/v3/certs",
                "issuer": "https://accounts.google.com",
                "audience": config.GOOGLE_CLIENT_ID,
            }
        elif provider_name == "azure":
            tenant_id = config.AZURE_TENANT_ID or "common"
            return {
                "jwks_url": f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys",
                "issuer": f"https://login.microsoftonline.com/{tenant_id}/v2.0",
                "audience": config.AZURE_CLIENT_ID,
            }
        else:
            logger.error(f"Unsupported provider: {provider_name}")
            raise InvalidTokenError(
                f"Unsupported provider for ID token verification: {provider_name}"
            )

    async def _get_provider_public_key_async(
        self, id_token: str, provider_config: Dict[str, str]
    ):
        """
        Get provider's public key for token verification with caching (async).
        """
        jwks_url = provider_config["jwks_url"]
        if (
            jwks_url in self._jwks_cache
            and jwks_url in self._jwks_cache_expiry
            and datetime.now() < self._jwks_cache_expiry[jwks_url]
        ):
            jwks = self._jwks_cache[jwks_url]
        else:
            try:
                async with httpx.AsyncClient() as client:
                    response = await client.get(jwks_url, timeout=10)
                    response.raise_for_status()
                    jwks = response.json()
                self._jwks_cache[jwks_url] = jwks
                self._jwks_cache_expiry[jwks_url] = datetime.now() + timedelta(hours=1)
            except httpx.HTTPError as e:
                logger.error(
                    f"Failed to fetch JWKS from {jwks_url}: {str(e)}", exc_info=True
                )
                raise InvalidTokenError(f"Failed to fetch JWKS: {str(e)}") from e

        header = jwt.get_unverified_header(id_token)
        kid = header.get("kid")
        if not kid:
            logger.error("ID token missing 'kid' in header")
            raise InvalidTokenError("ID token missing 'kid' in header")

        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                return jwt.algorithms.RSAAlgorithm.from_jwk(key)

        logger.error(f"Unable to find matching key for kid: {kid}")
        raise InvalidTokenError(f"Unable to find matching key for kid: {kid}")

    def _get_provider_public_key(self, id_token: str, provider_config: Dict[str, str]):
        """
        Get provider's public key for token verification with caching.
        """
        jwks_url = provider_config["jwks_url"]
        if (
            jwks_url in self._jwks_cache
            and jwks_url in self._jwks_cache_expiry
            and datetime.now() < self._jwks_cache_expiry[jwks_url]
        ):
            jwks = self._jwks_cache[jwks_url]
        else:
            try:
                with httpx.Client() as client:
                    response = client.get(jwks_url, timeout=10)
                    response.raise_for_status()
                    jwks = response.json()
                self._jwks_cache[jwks_url] = jwks
                self._jwks_cache_expiry[jwks_url] = datetime.now() + timedelta(hours=1)
            except httpx.HTTPError as e:
                logger.error(
                    f"Failed to fetch JWKS from {jwks_url}: {str(e)}", exc_info=True
                )
                raise InvalidTokenError(f"Failed to fetch JWKS: {str(e)}") from e

        header = jwt.get_unverified_header(id_token)
        kid = header.get("kid")
        if not kid:
            logger.error("ID token missing 'kid' in header")
            raise InvalidTokenError("ID token missing 'kid' in header")

        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                return jwt.algorithms.RSAAlgorithm.from_jwk(key)

        logger.error(f"Unable to find matching key for kid: {kid}")
        raise InvalidTokenError(f"Unable to find matching key for kid: {kid}")

    def _validate_id_token_claims(self, payload: Dict[str, Any], provider_name: str):
        """
        Validate additional ID token claims.
        """
        required_claims = ["iss", "aud", "exp", "iat"]
        missing_claims = [claim for claim in required_claims if claim not in payload]
        if missing_claims:
            logger.error(f"Missing required claims: {', '.join(missing_claims)}")
            raise InvalidTokenError(
                f"Missing required claims: {', '.join(missing_claims)}"
            )

        exp = payload.get("exp")
        if not isinstance(exp, datetime):
            logger.error("Invalid exp claim type")
            raise InvalidTokenError("Invalid exp claim type")
        if exp < datetime.now():
            logger.error("ID token has expired")
            raise InvalidTokenError("ID token has expired")

        iat = payload.get("iat")
        if not isinstance(iat, datetime):
            logger.error("Invalid iat claim type")
            raise InvalidTokenError("Invalid iat claim type")
        if iat > datetime.now() + timedelta(minutes=5):
            logger.error("ID token issued in the future")
            raise InvalidTokenError("ID token issued in the future")

        if provider_name == "google":
            if not payload.get("email_verified", False):
                logger.warning("Google ID token email not verified")
                # Optional: Could raise InvalidTokenError in strict mode
        elif provider_name == "azure":
            if config.AZURE_TENANT_ID and config.AZURE_TENANT_ID != "common":
                tid = payload.get("tid")
                if not tid:
                    logger.error("Azure ID token missing tenant ID")
                    raise InvalidTokenError("Azure ID token missing tenant ID")
                if tid != config.AZURE_TENANT_ID:
                    logger.error(f"Azure ID token from wrong tenant: {tid}")
                    raise InvalidTokenError(f"Azure ID token from wrong tenant: {tid}")
