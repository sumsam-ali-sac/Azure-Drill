"""
Secret management utilities for the authentication module.
Handles secure retrieval and management of cryptographic keys and secrets.
"""

import os
import base64
from typing import Optional, Union
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from root.authcommon.exceptions import AuthConfigurationError
from root.authcommon.config import config


class SecretManager:
    """Manages cryptographic secrets and keys for the authentication system."""

    def __init__(self):
        self._jwt_secret: Optional[str] = None
        self._private_key: Optional[
            Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]
        ] = None
        self._public_key: Optional[
            Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey]
        ] = None

    def get_jwt_secret(self) -> str:
        """Get JWT secret for HS256 algorithm."""
        if self._jwt_secret is None:
            secret = os.environ.get("JWT_SECRET") or config.SECRET_KEY
            if not secret:
                raise AuthConfigurationError("JWT secret not configured")
            self._jwt_secret = secret
        return self._jwt_secret

    def get_private_key(self) -> Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]:
        """Get private key for RS256/ES256 algorithms."""
        if self._private_key is None:
            private_key_data = config.JWT_PRIVATE_KEY
            if not private_key_data:
                raise AuthConfigurationError(
                    "Private key not configured for asymmetric algorithm"
                )

            try:
                # Try to decode if base64 encoded
                if not private_key_data.startswith("-----"):
                    private_key_data = base64.b64decode(private_key_data).decode(
                        "utf-8"
                    )

                self._private_key = serialization.load_pem_private_key(
                    private_key_data.encode("utf-8"),
                    password=None,
                    backend=default_backend(),
                )
            except Exception as e:
                raise AuthConfigurationError(f"Failed to load private key: {str(e)}")

        return self._private_key

    def get_public_key(self) -> Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey]:
        """Get public key for RS256/ES256 algorithms."""
        if self._public_key is None:
            public_key_data = config.JWT_PUBLIC_KEY
            if not public_key_data:
                # Try to derive from private key
                try:
                    private_key = self.get_private_key()
                    self._public_key = private_key.public_key()
                    return self._public_key
                except Exception:
                    raise AuthConfigurationError(
                        "Public key not configured and cannot derive from private key"
                    )

            try:
                # Try to decode if base64 encoded
                if not public_key_data.startswith("-----"):
                    public_key_data = base64.b64decode(public_key_data).decode("utf-8")

                self._public_key = serialization.load_pem_public_key(
                    public_key_data.encode("utf-8"), backend=default_backend()
                )
            except Exception as e:
                raise AuthConfigurationError(f"Failed to load public key: {str(e)}")

        return self._public_key

    def get_oauth_secret(self, provider: str) -> str:
        """Get OAuth client secret for specified provider."""
        if provider == "google":
            secret = config.GOOGLE_CLIENT_SECRET
        elif provider == "azure":
            secret = config.AZURE_CLIENT_SECRET
        else:
            raise AuthConfigurationError(f"Unknown OAuth provider: {provider}")

        if not secret:
            raise AuthConfigurationError(
                f"OAuth secret not configured for provider: {provider}"
            )

        return secret

    def get_oauth_client_id(self, provider: str) -> str:
        """Get OAuth client ID for specified provider."""
        if provider == "google":
            client_id = config.GOOGLE_CLIENT_ID
        elif provider == "azure":
            client_id = config.AZURE_CLIENT_ID
        else:
            raise AuthConfigurationError(f"Unknown OAuth provider: {provider}")

        if not client_id:
            raise AuthConfigurationError(
                f"OAuth client ID not configured for provider: {provider}"
            )

        return client_id

    def generate_rsa_keypair(self, key_size: int = 2048) -> tuple[str, str]:
        """Generate RSA key pair for RS256 algorithm."""
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=key_size, backend=default_backend()
        )

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        return private_pem, public_pem

    def generate_ec_keypair(self, curve=ec.SECP256R1()) -> tuple[str, str]:
        """Generate Elliptic Curve key pair for ES256 algorithm."""
        private_key = ec.generate_private_key(curve, default_backend())

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        return private_pem, public_pem


# Global secret manager instance
secret_manager = SecretManager()
