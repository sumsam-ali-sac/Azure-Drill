"""
Configuration module for loading environment variables.
Never hardcode secrets - always use environment variables.
"""

import os
from typing import Optional
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Configuration class for auth service settings."""
    
    # JWT Configuration
    JWT_SECRET: str = os.getenv("JWT_SECRET", "your-super-secret-jwt-key-change-in-production")
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
    
    # MongoDB Configuration
    MONGODB_URL: str = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
    DATABASE_NAME: str = os.getenv("DATABASE_NAME", "auth_service")
    
    # Google OAuth Configuration
    GOOGLE_CLIENT_ID: Optional[str] = os.getenv("GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET: Optional[str] = os.getenv("GOOGLE_CLIENT_SECRET")
    GOOGLE_REDIRECT_URI: str = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/auth/google/callback")
    
    # Azure OAuth Configuration
    AZURE_CLIENT_ID: Optional[str] = os.getenv("AZURE_CLIENT_ID")
    AZURE_CLIENT_SECRET: Optional[str] = os.getenv("AZURE_CLIENT_SECRET")
    AZURE_TENANT_ID: Optional[str] = os.getenv("AZURE_TENANT_ID")
    AZURE_REDIRECT_URI: str = os.getenv("AZURE_REDIRECT_URI", "http://localhost:8000/auth/azure/callback")
    
    # Cookie Configuration
    COOKIE_DOMAIN: Optional[str] = os.getenv("COOKIE_DOMAIN")  # None for same-origin
    COOKIE_PATH: str = os.getenv("COOKIE_PATH", "/")
    COOKIE_SECURE: bool = os.getenv("COOKIE_SECURE", "true").lower() == "true"
    COOKIE_SAMESITE: str = os.getenv("COOKIE_SAMESITE", "lax")  # lax, strict, none
    
    # Password Policy
    MIN_PASSWORD_LENGTH: int = int(os.getenv("MIN_PASSWORD_LENGTH", "8"))
    REQUIRE_UPPERCASE: bool = os.getenv("REQUIRE_UPPERCASE", "true").lower() == "true"
    REQUIRE_LOWERCASE: bool = os.getenv("REQUIRE_LOWERCASE", "true").lower() == "true"
    REQUIRE_NUMBERS: bool = os.getenv("REQUIRE_NUMBERS", "true").lower() == "true"
    REQUIRE_SPECIAL_CHARS: bool = os.getenv("REQUIRE_SPECIAL_CHARS", "true").lower() == "true"
    
    # OTP Configuration (for future use)
    OTP_EXPIRE_MINUTES: int = int(os.getenv("OTP_EXPIRE_MINUTES", "5"))
    OTP_ISSUER: str = os.getenv("OTP_ISSUER", "AuthService")

# Global config instance
config = Config()
