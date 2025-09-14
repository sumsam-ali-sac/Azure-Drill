"""
One-Time Password (OTP) utilities for two-factor authentication.
Supports TOTP (Time-based OTP) with email delivery and verification.
"""

import pyotp
import secrets
import qrcode
import io
import base64
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Tuple
from .configs import config
from .constants import (
    OTP_DIGITS,
    OTP_INTERVAL,
    OTP_WINDOW,
    OTP_SECRET_LENGTH,
    EMAIL_TEMPLATE_OTP
)
from .exceptions import OTPInvalidError, EmailSendError
from .utils import email_manager, rate_limiter


class OTPManager:
    """Manages OTP generation, verification, and delivery."""
    
    def __init__(self):
        self.otp_secrets: Dict[str, Dict[str, Any]] = {}  # In-memory storage (use Redis in production)
    
    def generate_otp_secret(self, user_id: str) -> str:
        """
        Generate a new OTP secret for a user.
        
        Args:
            user_id: User identifier
        
        Returns:
            Base32 encoded OTP secret
        """
        secret = pyotp.random_base32(length=OTP_SECRET_LENGTH)
        
        # Store secret with metadata (use Redis/database in production)
        self.otp_secrets[user_id] = {
            "secret": secret,
            "created_at": datetime.now(timezone.utc),
            "attempts": 0,
            "last_used": None
        }
        
        return secret
    
    def get_otp_secret(self, user_id: str) -> Optional[str]:
        """
        Get existing OTP secret for a user.
        
        Args:
            user_id: User identifier
        
        Returns:
            OTP secret if exists, None otherwise
        """
        user_otp = self.otp_secrets.get(user_id)
        if user_otp:
            # Check if secret is still valid (not expired)
            created_at = user_otp["created_at"]
            if datetime.now(timezone.utc) - created_at < timedelta(seconds=config.OTP_EXPIRY_SECONDS):
                return user_otp["secret"]
            else:
                # Clean up expired secret
                del self.otp_secrets[user_id]
        return None
    
    def generate_otp_code(self, secret: str) -> str:
        """
        Generate current OTP code from secret.
        
        Args:
            secret: OTP secret
        
        Returns:
            Current OTP code
        """
        totp = pyotp.TOTP(secret, digits=OTP_DIGITS, interval=OTP_INTERVAL)
        return totp.now()
    
    def verify_otp_code(self, user_id: str, provided_code: str, secret: Optional[str] = None) -> bool:
        """
        Verify provided OTP code.
        
        Args:
            user_id: User identifier
            provided_code: OTP code provided by user
            secret: Optional OTP secret (if not provided, will look up by user_id)
        
        Returns:
            True if OTP code is valid
        """
        if not secret:
            secret = self.get_otp_secret(user_id)
            if not secret:
                raise OTPInvalidError("No active OTP session found")
        
        # Check rate limiting
        user_otp = self.otp_secrets.get(user_id, {})
        attempts = user_otp.get("attempts", 0)
        
        if attempts >= 5:  # Max 5 attempts
            raise OTPInvalidError("Too many OTP attempts. Please request a new code.")
        
        # Verify code with time window
        totp = pyotp.TOTP(secret, digits=OTP_DIGITS, interval=OTP_INTERVAL)
        is_valid = totp.verify(provided_code, valid_window=OTP_WINDOW)
        
        # Update attempts counter
        if user_id in self.otp_secrets:
            self.otp_secrets[user_id]["attempts"] = attempts + 1
            if is_valid:
                self.otp_secrets[user_id]["last_used"] = datetime.now(timezone.utc)
        
        if not is_valid:
            raise OTPInvalidError("Invalid or expired OTP code")
        
        return True
    
    @rate_limiter.limit("otp_send", config.RATE_LIMIT_OTP_PER_MIN, 60)
    def send_otp_email(self, email: str, user_id: str, action: str = "login") -> bool:
        """
        Generate and send OTP code via email.
        
        Args:
            email: User email address
            user_id: User identifier
            action: Action requiring OTP (login, reset, etc.)
        
        Returns:
            True if OTP was sent successfully
        """
        try:
            # Generate or get existing secret
            secret = self.get_otp_secret(user_id)
            if not secret:
                secret = self.generate_otp_secret(user_id)
            
            # Generate current OTP code
            otp_code = self.generate_otp_code(secret)
            
            # Prepare email content
            subject = f"Your OTP Code - {config.APP_NAME}"
            body = EMAIL_TEMPLATE_OTP.format(
                app_name=config.APP_NAME,
                otp_code=otp_code,
                expiry_minutes=config.OTP_EXPIRY_SECONDS // 60,
                action=action
            )
            
            # Send email
            email_manager.send_email(email, subject, body)
            
            return True
            
        except Exception as e:
            raise EmailSendError(f"Failed to send OTP email: {str(e)}")
    
    def generate_qr_code(self, user_email: str, secret: str, issuer: Optional[str] = None) -> str:
        """
        Generate QR code for OTP setup in authenticator apps.
        
        Args:
            user_email: User email address
            secret: OTP secret
            issuer: Service name (defaults to app name)
        
        Returns:
            Base64 encoded QR code image
        """
        issuer = issuer or config.APP_NAME
        
        # Create TOTP URI
        totp = pyotp.TOTP(secret, digits=OTP_DIGITS, interval=OTP_INTERVAL)
        provisioning_uri = totp.provisioning_uri(
            name=user_email,
            issuer_name=issuer
        )
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        # Create image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        img_str = base64.b64encode(buffer.getvalue()).decode()
        
        return f"data:image/png;base64,{img_str}"
    
    def verify_backup_code(self, user_id: str, backup_code: str) -> bool:
        """
        Verify backup recovery code.
        
        Args:
            user_id: User identifier
            backup_code: Backup code provided by user
        
        Returns:
            True if backup code is valid
        """
        # TODO: Implement backup code verification
        # This would typically check against stored backup codes in database
        return False
    
    def generate_backup_codes(self, user_id: str, count: int = 10) -> list[str]:
        """
        Generate backup recovery codes.
        
        Args:
            user_id: User identifier
            count: Number of backup codes to generate
        
        Returns:
            List of backup codes
        """
        backup_codes = []
        for _ in range(count):
            # Generate 8-character alphanumeric code
            code = secrets.token_hex(4).upper()
            backup_codes.append(f"{code[:4]}-{code[4:]}")
        
        # TODO: Store backup codes in database (hashed)
        
        return backup_codes
    
    def cleanup_expired_secrets(self):
        """Clean up expired OTP secrets from memory."""
        now = datetime.now(timezone.utc)
        expired_users = []
        
        for user_id, otp_data in self.otp_secrets.items():
            created_at = otp_data["created_at"]
            if now - created_at > timedelta(seconds=config.OTP_EXPIRY_SECONDS):
                expired_users.append(user_id)
        
        for user_id in expired_users:
            del self.otp_secrets[user_id]
    
    def get_otp_status(self, user_id: str) -> Dict[str, Any]:
        """
        Get OTP status for a user.
        
        Args:
            user_id: User identifier
        
        Returns:
            OTP status information
        """
        user_otp = self.otp_secrets.get(user_id)
        
        if not user_otp:
            return {
                "has_active_otp": False,
                "attempts_remaining": 0,
                "expires_at": None
            }
        
        created_at = user_otp["created_at"]
        expires_at = created_at + timedelta(seconds=config.OTP_EXPIRY_SECONDS)
        attempts_used = user_otp.get("attempts", 0)
        
        return {
            "has_active_otp": datetime.now(timezone.utc) < expires_at,
            "attempts_remaining": max(0, 5 - attempts_used),
            "expires_at": expires_at,
            "created_at": created_at,
            "last_used": user_otp.get("last_used")
        }
    
    def invalidate_otp(self, user_id: str):
        """
        Invalidate/remove OTP secret for a user.
        
        Args:
            user_id: User identifier
        """
        if user_id in self.otp_secrets:
            del self.otp_secrets[user_id]


# Global OTP manager instance
otp_manager = OTPManager()
