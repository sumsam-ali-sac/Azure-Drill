"""
One-Time Password (OTP) management with TOTP and HOTP support.
Includes backup codes, rate limiting, and multi-factor authentication.
"""

import pyotp
import qrcode
import io
import base64
import secrets
import time
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
import logging

from auth.configs import config
from auth.constants import OTP_EXPIRY_SECONDS, OTP_ISSUER_NAME
from auth.exceptions import OTPInvalidError, RateLimitExceededError
from auth.utils.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)


class OTPManager:
    """
    Advanced OTP management with TOTP/HOTP support.
    
    Features:
    - Time-based OTP (TOTP) for authenticator apps
    - Counter-based OTP (HOTP) for SMS/email
    - QR code generation for authenticator setup
    - Backup codes generation and validation
    - Rate limiting and brute force protection
    - Multiple OTP methods per user
    """
    
    def __init__(self):
        self.rate_limiter = RateLimiter()
        self.failed_attempts = {}  # In production, use Redis
        logger.info("OTPManager initialized")
    
    def generate_secret(self, length: int = 32) -> str:
        """
        Generate cryptographically secure OTP secret.
        
        Args:
            length: Secret length in bytes
            
        Returns:
            Base32 encoded secret
        """
        return pyotp.random_base32(length=length)
    
    def generate_totp_uri(
        self, 
        secret: str, 
        email: str, 
        issuer: str = None
    ) -> str:
        """
        Generate TOTP URI for authenticator apps.
        
        Args:
            secret: OTP secret
            email: User email
            issuer: Service name
            
        Returns:
            TOTP URI string
        """
        issuer = issuer or config.APP_NAME
        
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(
            name=email,
            issuer_name=issuer
        )
    
    def generate_qr_code(
        self, 
        secret: str, 
        email: str, 
        issuer: str = None
    ) -> str:
        """
        Generate QR code for TOTP setup.
        
        Args:
            secret: OTP secret
            email: User email
            issuer: Service name
            
        Returns:
            Base64 encoded QR code image
        """
        uri = self.generate_totp_uri(secret, email, issuer)
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        
        # Create image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        img_str = base64.b64encode(buffer.getvalue()).decode()
        
        logger.info(f"QR code generated for: {email}")
        return f"data:image/png;base64,{img_str}"
    
    def generate_code(self, secret: str, method: str = "totp") -> str:
        """
        Generate OTP code.
        
        Args:
            secret: OTP secret
            method: OTP method (totp, hotp)
            
        Returns:
            6-digit OTP code
        """
        if method == "totp":
            totp = pyotp.TOTP(secret, interval=config.OTP_EXPIRY_SECONDS)
            return totp.now()
        elif method == "hotp":
            # For HOTP, you'd need to track counter per user
            # This is simplified for demonstration
            hotp = pyotp.HOTP(secret)
            return hotp.at(int(time.time()) // 30)  # Use time-based counter
        else:
            raise ValueError(f"Unsupported OTP method: {method}")
    
    async def verify_code(
        self, 
        provided_code: str, 
        secret: str, 
        user_id: str,
        method: str = "totp",
        window: int = 1
    ) -> bool:
        """
        Verify OTP code with rate limiting and brute force protection.
        
        Args:
            provided_code: Code provided by user
            secret: OTP secret
            user_id: User identifier for rate limiting
            method: OTP method (totp, hotp)
            window: Time window for TOTP validation
            
        Returns:
            True if code is valid
            
        Raises:
            RateLimitExceededError: Too many failed attempts
            OTPInvalidError: Invalid code
        """
        # Rate limiting
        await self.rate_limiter.check_limit(
            f"otp_verify:{user_id}",
            config.RATE_LIMIT_OTP_PER_MIN,
            60
        )
        
        # Check failed attempts
        failed_count = self.failed_attempts.get(user_id, 0)
        if failed_count >= 5:  # Lock after 5 failed attempts
            logger.warning(f"OTP verification locked for user: {user_id}")
            raise RateLimitExceededError("Too many failed OTP attempts")
        
        try:
            if method == "totp":
                totp = pyotp.TOTP(secret, interval=config.OTP_EXPIRY_SECONDS)
                is_valid = totp.verify(provided_code, valid_window=window)
            elif method == "hotp":
                hotp = pyotp.HOTP(secret)
                # In production, you'd track the counter per user
                counter = int(time.time()) // 30
                is_valid = hotp.verify(provided_code, counter)
            else:
                raise ValueError(f"Unsupported OTP method: {method}")
            
            if is_valid:
                # Reset failed attempts on success
                self.failed_attempts.pop(user_id, None)
                logger.info(f"OTP verified successfully for user: {user_id}")
                return True
            else:
                # Increment failed attempts
                self.failed_attempts[user_id] = failed_count + 1
                logger.warning(f"Invalid OTP for user: {user_id}")
                raise OTPInvalidError("Invalid or expired OTP code")
                
        except Exception as e:
            if not isinstance(e, (OTPInvalidError, RateLimitExceededError)):
                logger.error(f"OTP verification error: {str(e)}")
                raise OTPInvalidError("OTP verification failed")
            raise
    
    def generate_backup_codes(self, count: int = 10) -> List[str]:
        """
        Generate backup codes for account recovery.
        
        Args:
            count: Number of backup codes to generate
            
        Returns:
            List of backup codes
        """
        codes = []
        for _ in range(count):
            # Generate 8-character alphanumeric code
            code = ''.join(secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') 
                          for _ in range(8))
            # Format as XXXX-XXXX
            formatted_code = f"{code[:4]}-{code[4:]}"
            codes.append(formatted_code)
        
        logger.info(f"Generated {count} backup codes")
        return codes
    
    def verify_backup_code(
        self, 
        provided_code: str, 
        valid_codes: List[str],
        user_id: str
    ) -> Tuple[bool, List[str]]:
        """
        Verify backup code and remove it from valid codes.
        
        Args:
            provided_code: Code provided by user
            valid_codes: List of valid backup codes
            user_id: User identifier
            
        Returns:
            Tuple of (is_valid, remaining_codes)
        """
        # Normalize code format
        normalized_code = provided_code.upper().replace('-', '')
        if len(normalized_code) == 8:
            formatted_code = f"{normalized_code[:4]}-{normalized_code[4:]}"
        else:
            formatted_code = provided_code.upper()
        
        if formatted_code in valid_codes:
            # Remove used code
            remaining_codes = [code for code in valid_codes if code != formatted_code]
            logger.info(f"Backup code used by user: {user_id}")
            return True, remaining_codes
        
        logger.warning(f"Invalid backup code for user: {user_id}")
        return False, valid_codes
    
    def is_setup_complete(self, user_otp_data: Dict[str, Any]) -> bool:
        """
        Check if OTP setup is complete for user.
        
        Args:
            user_otp_data: User's OTP configuration data
            
        Returns:
            True if setup is complete
        """
        required_fields = ["secret", "is_verified"]
        return all(field in user_otp_data for field in required_fields) and \
               user_otp_data.get("is_verified", False)
    
    def get_remaining_time(self, interval: int = None) -> int:
        """
        Get remaining time until next TOTP code.
        
        Args:
            interval: TOTP interval in seconds
            
        Returns:
            Seconds until next code
        """
        interval = interval or config.OTP_EXPIRY_SECONDS
        return interval - (int(time.time()) % interval)
    
    async def send_otp_email(self, email: str, code: str, user_name: str = "User"):
        """
        Send OTP code via email.
        
        Args:
            email: Recipient email
            code: OTP code
            user_name: User's name for personalization
        """
        from auth.utils.email_service import EmailService
        
        email_service = EmailService()
        await email_service.send_otp_email(email, code, user_name)
    
    async def send_otp_sms(self, phone: str, code: str):
        """
        Send OTP code via SMS.
        
        Args:
            phone: Phone number
            code: OTP code
        """
        # Implementation would depend on SMS provider (Twilio, AWS SNS, etc.)
        # This is a placeholder for SMS functionality
        logger.info(f"SMS OTP sent to: {phone[-4:]}")  # Log last 4 digits only
        pass
    
    def cleanup_expired_attempts(self):
        """Clean up expired failed attempt records."""
        # In production, this would clean up Redis entries
        # For now, just clear the in-memory dict periodically
        current_time = time.time()
        if not hasattr(self, '_last_cleanup') or current_time - self._last_cleanup > 3600:
            self.failed_attempts.clear()
            self._last_cleanup = current_time
            logger.info("Cleaned up expired OTP attempt records")
