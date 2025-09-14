"""
General utility functions for the authentication module.
Includes email sending, rate limiting, CSRF protection, and other helpers.
"""

import smtplib
import secrets
import hashlib
import hmac
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, Callable, List
from functools import wraps
from .configs import config
from .constants import (
    CSRF_TOKEN_LENGTH,
    RATE_LIMIT_KEY_LOGIN,
    RATE_LIMIT_KEY_OTP,
    RATE_LIMIT_KEY_RESET,
    EMAIL_TEMPLATE_PASSWORD_RESET,
    EMAIL_TEMPLATE_WELCOME
)
from .exceptions import (
    RateLimitExceededError,
    EmailSendError,
    CSRFError
)


class EmailManager:
    """Manages email sending with SMTP configuration."""
    
    def __init__(self):
        self.smtp_configured = bool(config.SMTP_USER and config.SMTP_PASSWORD)
    
    def send_email(
        self,
        to_email: str,
        subject: str,
        body: str,
        html_body: Optional[str] = None,
        from_email: Optional[str] = None
    ) -> bool:
        """
        Send email using configured SMTP settings.
        
        Args:
            to_email: Recipient email address
            subject: Email subject
            body: Plain text email body
            html_body: Optional HTML email body
            from_email: Optional sender email (defaults to config)
        
        Returns:
            True if email was sent successfully
        """
        if not self.smtp_configured:
            raise EmailSendError("SMTP not configured")
        
        from_email = from_email or config.FROM_EMAIL or config.SMTP_USER
        
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = from_email
            msg['To'] = to_email
            
            # Add plain text part
            text_part = MIMEText(body, 'plain')
            msg.attach(text_part)
            
            # Add HTML part if provided
            if html_body:
                html_part = MIMEText(html_body, 'html')
                msg.attach(html_part)
            
            # Send email
            with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT) as server:
                if config.SMTP_USE_TLS:
                    server.starttls()
                server.login(config.SMTP_USER, config.SMTP_PASSWORD)
                server.send_message(msg)
            
            return True
            
        except Exception as e:
            raise EmailSendError(f"Failed to send email: {str(e)}")
    
    def send_password_reset_email(self, email: str, reset_token: str) -> bool:
        """
        Send password reset email.
        
        Args:
            email: User email address
            reset_token: Password reset token
        
        Returns:
            True if email was sent successfully
        """
        reset_link = f"{config.FRONTEND_URL}/reset-password?token={reset_token}"
        
        subject = f"Password Reset Request - {config.APP_NAME}"
        body = EMAIL_TEMPLATE_PASSWORD_RESET.format(
            app_name=config.APP_NAME,
            reset_link=reset_link,
            expiry_minutes=15
        )
        
        return self.send_email(email, subject, body)
    
    def send_welcome_email(self, email: str, user_name: str) -> bool:
        """
        Send welcome email to new users.
        
        Args:
            email: User email address
            user_name: User's name
        
        Returns:
            True if email was sent successfully
        """
        subject = f"Welcome to {config.APP_NAME}!"
        body = EMAIL_TEMPLATE_WELCOME.format(
            app_name=config.APP_NAME,
            user_name=user_name
        )
        
        return self.send_email(email, subject, body)


class RateLimiter:
    """In-memory rate limiter (use Redis in production)."""
    
    def __init__(self):
        self.requests: Dict[str, List[float]] = {}
    
    def is_allowed(self, key: str, limit: int, window_seconds: int) -> bool:
        """
        Check if request is allowed under rate limit.
        
        Args:
            key: Rate limit key (e.g., user ID, IP address)
            limit: Maximum requests allowed
            window_seconds: Time window in seconds
        
        Returns:
            True if request is allowed
        """
        now = time.time()
        window_start = now - window_seconds
        
        # Clean up old requests
        if key in self.requests:
            self.requests[key] = [req_time for req_time in self.requests[key] if req_time > window_start]
        else:
            self.requests[key] = []
        
        # Check if limit exceeded
        if len(self.requests[key]) >= limit:
            return False
        
        # Add current request
        self.requests[key].append(now)
        return True
    
    def limit(self, key_prefix: str, limit: int, window_seconds: int):
        """
        Decorator for rate limiting functions.
        
        Args:
            key_prefix: Prefix for rate limit key
            limit: Maximum requests allowed
            window_seconds: Time window in seconds
        """
        def decorator(func: Callable):
            @wraps(func)
            def wrapper(*args, **kwargs):
                # Generate rate limit key (you might want to customize this)
                key = f"{key_prefix}:global"  # Simple global rate limiting
                
                if not self.is_allowed(key, limit, window_seconds):
                    raise RateLimitExceededError()
                
                return func(*args, **kwargs)
            return wrapper
        return decorator
    
    def get_remaining_requests(self, key: str, limit: int, window_seconds: int) -> int:
        """
        Get remaining requests for a key.
        
        Args:
            key: Rate limit key
            limit: Maximum requests allowed
            window_seconds: Time window in seconds
        
        Returns:
            Number of remaining requests
        """
        now = time.time()
        window_start = now - window_seconds
        
        if key in self.requests:
            recent_requests = [req_time for req_time in self.requests[key] if req_time > window_start]
            return max(0, limit - len(recent_requests))
        
        return limit
    
    def reset_key(self, key: str):
        """Reset rate limit for a specific key."""
        if key in self.requests:
            del self.requests[key]


class CSRFManager:
    """CSRF token management."""
    
    def __init__(self):
        self.tokens: Dict[str, Dict[str, Any]] = {}
    
    def generate_csrf_token(self, session_id: str) -> str:
        """
        Generate CSRF token for a session.
        
        Args:
            session_id: Session identifier
        
        Returns:
            CSRF token
        """
        token = secrets.token_urlsafe(CSRF_TOKEN_LENGTH)
        
        self.tokens[session_id] = {
            "token": token,
            "created_at": datetime.now(timezone.utc),
            "used": False
        }
        
        return token
    
    def verify_csrf_token(self, session_id: str, provided_token: str, single_use: bool = True) -> bool:
        """
        Verify CSRF token.
        
        Args:
            session_id: Session identifier
            provided_token: Token provided by client
            single_use: Whether token should be invalidated after use
        
        Returns:
            True if token is valid
        """
        if session_id not in self.tokens:
            return False
        
        token_data = self.tokens[session_id]
        stored_token = token_data["token"]
        created_at = token_data["created_at"]
        
        # Check if token is expired (1 hour)
        if datetime.now(timezone.utc) - created_at > timedelta(hours=1):
            del self.tokens[session_id]
            return False
        
        # Check if token was already used (for single-use tokens)
        if single_use and token_data.get("used", False):
            return False
        
        # Verify token using constant-time comparison
        if not hmac.compare_digest(stored_token, provided_token):
            return False
        
        # Mark as used if single-use
        if single_use:
            self.tokens[session_id]["used"] = True
        
        return True
    
    def invalidate_csrf_token(self, session_id: str):
        """Invalidate CSRF token for a session."""
        if session_id in self.tokens:
            del self.tokens[session_id]


class SecurityUtils:
    """General security utilities."""
    
    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """Generate cryptographically secure token."""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def generate_state_token() -> str:
        """Generate OAuth state token."""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def hash_token(token: str, salt: Optional[str] = None) -> str:
        """Hash a token with optional salt."""
        if salt is None:
            salt = secrets.token_hex(16)
        
        combined = f"{token}{salt}"
        hashed = hashlib.sha256(combined.encode()).hexdigest()
        return f"{salt}:{hashed}"
    
    @staticmethod
    def verify_hashed_token(token: str, hashed_token: str) -> bool:
        """Verify token against its hash."""
        try:
            salt, expected_hash = hashed_token.split(":", 1)
            combined = f"{token}{salt}"
            actual_hash = hashlib.sha256(combined.encode()).hexdigest()
            return hmac.compare_digest(expected_hash, actual_hash)
        except ValueError:
            return False
    
    @staticmethod
    def sanitize_email(email: str) -> str:
        """Sanitize email address."""
        return email.lower().strip()
    
    @staticmethod
    def is_safe_redirect_url(url: str, allowed_hosts: Optional[List[str]] = None) -> bool:
        """Check if redirect URL is safe."""
        if not url:
            return False
        
        # Check for absolute URLs
        if url.startswith(('http://', 'https://')):
            from urllib.parse import urlparse
            parsed = urlparse(url)
            
            if allowed_hosts:
                return parsed.netloc in allowed_hosts
            else:
                # Only allow same host as configured frontend URL
                from urllib.parse import urlparse as parse_frontend
                frontend_host = parse_frontend(config.FRONTEND_URL).netloc
                return parsed.netloc == frontend_host
        
        # Relative URLs are generally safe
        return url.startswith('/')


class ValidationUtils:
    """Input validation utilities."""
    
    @staticmethod
    def is_valid_email(email: str) -> bool:
        """Validate email format."""
        import re
        from .constants import REGEX_EMAIL
        return bool(re.match(REGEX_EMAIL, email))
    
    @staticmethod
    def is_valid_uuid(uuid_string: str) -> bool:
        """Validate UUID format."""
        import re
        from .constants import REGEX_UUID
        return bool(re.match(REGEX_UUID, uuid_string))
    
    @staticmethod
    def sanitize_input(input_string: str, max_length: int = 1000) -> str:
        """Sanitize user input."""
        if not input_string:
            return ""
        
        # Remove null bytes and control characters
        sanitized = ''.join(char for char in input_string if ord(char) >= 32 or char in '\t\n\r')
        
        # Truncate to max length
        return sanitized[:max_length]


# Global utility instances
email_manager = EmailManager()
rate_limiter = RateLimiter()
csrf_manager = CSRFManager()
security_utils = SecurityUtils()
validation_utils = ValidationUtils()
