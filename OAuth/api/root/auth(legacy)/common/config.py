"""
Configuration management for the authentication module.
Handles environment variables, validation, and default settings.
"""

import os
from typing import Optional, List
from pydantic_settings import BaseSettings
from pydantic import Field, field_validator


class AuthConfig(BaseSettings):
    """
    Authentication configuration with environment variable support.
    Provides secure defaults and validation for all auth settings.
    """

    # JWT Configuration
    SECRET_KEY: str = Field(..., description="Secret key for HS256 JWT signing")
    JWT_ALGORITHM: str = Field(
        default="RS256", description="JWT algorithm (HS256, RS256, ES256)"
    )
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(
        default=15, description="Access token expiry in minutes"
    )
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(
        default=30, description="Refresh token expiry in days"
    )

    # RSA/ECDSA Keys for RS256/ES256
    JWT_PRIVATE_KEY: Optional[str] = Field(
        default=None, description="Private key for RS256/ES256"
    )
    JWT_PUBLIC_KEY: Optional[str] = Field(
        default=None, description="Public key for RS256/ES256"
    )

    # OAuth Configuration
    GOOGLE_CLIENT_ID: Optional[str] = Field(
        default=None, description="Google OAuth client ID"
    )
    GOOGLE_CLIENT_SECRET: Optional[str] = Field(
        default=None, description="Google OAuth client secret"
    )
    AZURE_CLIENT_ID: Optional[str] = Field(
        default=None, description="Azure AD client ID"
    )
    AZURE_CLIENT_SECRET: Optional[str] = Field(
        default=None, description="Azure AD client secret"
    )
    AZURE_TENANT_ID: Optional[str] = Field(
        default=None, description="Azure AD tenant ID"
    )

    # JWKS URLs for token verification
    GOOGLE_JWKS_URL: str = Field(
        default="https://www.googleapis.com/oauth2/v3/certs",
        description="Google JWKS URL",
    )
    AZURE_JWKS_URL: Optional[str] = Field(default=None, description="Azure AD JWKS URL")

    # Email Configuration
    SMTP_HOST: str = Field(default="smtp.gmail.com", description="SMTP server host")
    SMTP_PORT: int = Field(default=587, description="SMTP server port")
    SMTP_USER: Optional[str] = Field(default=None, description="SMTP username")
    SMTP_PASSWORD: Optional[str] = Field(default=None, description="SMTP password")
    SMTP_USE_TLS: bool = Field(default=True, description="Use TLS for SMTP")
    FROM_EMAIL: Optional[str] = Field(default=None, description="From email address")

    # Security Settings
    REQUIRE_OTP: bool = Field(default=True, description="Require OTP for local login")
    OTP_EXPIRY_SECONDS: int = Field(
        default=300, description="OTP expiry time in seconds"
    )
    MIN_PASSWORD_LENGTH: int = Field(default=12, description="Minimum password length")

    # Rate Limiting
    RATE_LIMIT_LOGIN_PER_MIN: int = Field(
        default=5, description="Login attempts per minute"
    )
    RATE_LIMIT_OTP_PER_MIN: int = Field(
        default=3, description="OTP requests per minute"
    )
    RATE_LIMIT_RESET_PER_HOUR: int = Field(
        default=3, description="Password reset requests per hour"
    )

    # Session Configuration
    SESSION_COOKIE_NAME: str = Field(
        default="refresh_token", description="Session cookie name"
    )
    SESSION_COOKIE_SECURE: bool = Field(default=True, description="Secure cookie flag")
    SESSION_COOKIE_HTTPONLY: bool = Field(
        default=True, description="HTTP-only cookie flag"
    )
    SESSION_COOKIE_SAMESITE: str = Field(
        default="strict", description="SameSite cookie attribute"
    )

    # Application Settings
    APP_NAME: str = Field(default="Advanced Auth App", description="Application name")
    FRONTEND_URL: str = Field(
        default="http://localhost:3000", description="Frontend URL for redirects"
    )
    BACKEND_URL: str = Field(default="http://localhost:8000", description="Backend URL")

    # Redis Configuration (for rate limiting and caching)
    REDIS_URL: Optional[str] = Field(default=None, description="Redis URL for caching")

    # Logging
    LOG_LEVEL: str = Field(default="INFO", description="Logging level")

    @field_validator("JWT_ALGORITHM")
    @classmethod
    def validate_jwt_algorithm(cls, v):
        allowed = ["HS256", "RS256", "ES256"]
        if v not in allowed:
            raise ValueError(f"JWT_ALGORITHM must be one of {allowed}")
        return v

    @field_validator("JWT_PRIVATE_KEY", "JWT_PUBLIC_KEY")
    @classmethod
    def validate_asymmetric_keys(cls, v, info):
        algorithm = info.data.get("JWT_ALGORITHM", "HS256")
        if algorithm in ["RS256", "ES256"] and not v:
            raise ValueError(f"Private and public keys required for {algorithm}")
        return v

    @field_validator("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET")
    @classmethod
    def validate_google_oauth(cls, v, info):
        # If one is provided, both should be provided
        data = info.data
        client_id = data.get("GOOGLE_CLIENT_ID")
        client_secret = data.get("GOOGLE_CLIENT_SECRET")
        if (client_id and not client_secret) or (client_secret and not client_id):
            raise ValueError(
                "Both GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET must be provided"
            )
        return v

    @field_validator("AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID")
    @classmethod
    def validate_azure_oauth(cls, v, info):
        # If any Azure field is provided, all should be provided
        data = info.data
        client_id = data.get("AZURE_CLIENT_ID")
        client_secret = data.get("AZURE_CLIENT_SECRET")
        tenant_id = data.get("AZURE_TENANT_ID")

        azure_fields = [client_id, client_secret, tenant_id]
        if any(azure_fields) and not all(azure_fields):
            raise ValueError(
                "All Azure OAuth fields (CLIENT_ID, CLIENT_SECRET, TENANT_ID) must be provided"
            )
        return v

    @property
    def azure_jwks_url_computed(self) -> Optional[str]:
        """Compute Azure JWKS URL from tenant ID if not explicitly provided."""
        if self.AZURE_JWKS_URL:
            return self.AZURE_JWKS_URL
        if self.AZURE_TENANT_ID:
            return f"https://login.microsoftonline.com/{self.AZURE_TENANT_ID}/discovery/v2.0/keys"
        return None

    @property
    def is_google_oauth_enabled(self) -> bool:
        """Check if Google OAuth is properly configured."""
        return bool(self.GOOGLE_CLIENT_ID and self.GOOGLE_CLIENT_SECRET)

    @property
    def is_azure_oauth_enabled(self) -> bool:
        """Check if Azure OAuth is properly configured."""
        return bool(
            self.AZURE_CLIENT_ID and self.AZURE_CLIENT_SECRET and self.AZURE_TENANT_ID
        )

    @property
    def enabled_oauth_providers(self) -> List[str]:
        """Get list of enabled OAuth providers."""
        providers = []
        if self.is_google_oauth_enabled:
            providers.append("google")
        if self.is_azure_oauth_enabled:
            providers.append("azure")
        return providers

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
    }


# Global configuration instance
config = AuthConfig()
