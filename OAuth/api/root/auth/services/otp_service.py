"""
OTP (One-Time Password) service for TOTP and HOTP authentication.
"""

from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
from auth_service.base.auth_base import BaseAuthService
from auth_service.models.user import User
from auth_service.managers.user_manager import UserManager
from auth_service.managers.token_manager import TokenManager
from auth_service.utils.security import SecurityUtils
from auth_service.exceptions.auth_exceptions import (
    ValidationError, 
    InvalidCredentialsError,
    OTPError
)
from auth_service.config import config
import pyotp
import qrcode
import io
import base64

class OTPService(BaseAuthService):
    """
    OTP service for Time-based One-Time Password (TOTP) and HMAC-based One-Time Password (HOTP).
    
    Provides:
    - TOTP setup and verification (Google Authenticator compatible)
    - HOTP setup and verification
    - QR code generation for easy setup
    - Backup codes generation
    - OTP-based authentication
    """
    
    def __init__(self, user_manager: UserManager, token_manager: TokenManager, 
                 security_utils: SecurityUtils):
        """Initialize OTP service with required dependencies."""
        super().__init__()
        self._user_manager = user_manager
        self._token_manager = token_manager
        self._security_utils = security_utils
    
    def setup_totp(self, user_id: str) -> Dict[str, Any]:
        """
        Set up TOTP for a user.
        
        Args:
            user_id: ID of the user
            
        Returns:
            Dict with secret, QR code URI, and backup codes
            
        Raises:
            ValidationError: If user not found
        """
        user = self._user_manager.get_by_id(user_id)
        if not user:
            raise ValidationError("User not found")
        
        # Generate new OTP secret
        otp_secret = self._security_utils.generate_otp_secret()
        
        # Generate TOTP URI for QR code
        totp_uri = self._security_utils.generate_totp_uri(
            user.email, 
            otp_secret, 
            config.OTP_ISSUER
        )
        
        # Generate QR code
        qr_code_data = self._generate_qr_code(totp_uri)
        
        # Generate backup codes
        backup_codes = self._generate_backup_codes()
        
        # Update user with OTP secret (but don't enable until verified)
        user.otp_secret = otp_secret
        self._user_manager.update_user(user)
        
        return {
            "secret": otp_secret,
            "qr_code_uri": totp_uri,
            "qr_code_data": qr_code_data,
            "backup_codes": backup_codes,
            "setup_complete": False
        }
    
    async def setup_totp_async(self, user_id: str) -> Dict[str, Any]:
        """Set up TOTP for a user (async)."""
        user = await self._user_manager.get_by_id_async(user_id)
        if not user:
            raise ValidationError("User not found")
        
        # Generate new OTP secret
        otp_secret = self._security_utils.generate_otp_secret()
        
        # Generate TOTP URI for QR code
        totp_uri = self._security_utils.generate_totp_uri(
            user.email, 
            otp_secret, 
            config.OTP_ISSUER
        )
        
        # Generate QR code
        qr_code_data = self._generate_qr_code(totp_uri)
        
        # Generate backup codes
        backup_codes = self._generate_backup_codes()
        
        # Update user with OTP secret (but don't enable until verified)
        user.otp_secret = otp_secret
        await self._user_manager.update_user_async(user)
        
        return {
            "secret": otp_secret,
            "qr_code_uri": totp_uri,
            "qr_code_data": qr_code_data,
            "backup_codes": backup_codes,
            "setup_complete": False
        }
    
    def verify_totp_setup(self, user_id: str, otp_code: str) -> bool:
        """
        Verify TOTP setup by validating the first OTP code.
        
        Args:
            user_id: ID of the user
            otp_code: OTP code from authenticator app
            
        Returns:
            True if setup is verified and enabled
            
        Raises:
            ValidationError: If user not found or OTP not set up
            OTPError: If OTP code is invalid
        """
        user = self._user_manager.get_by_id(user_id)
        if not user:
            raise ValidationError("User not found")
        
        if not user.otp_secret:
            raise ValidationError("OTP not set up for this user")
        
        # Verify the OTP code
        if not self._security_utils.verify_totp(user.otp_secret, otp_code):
            raise OTPError("Invalid OTP code")
        
        # Mark OTP as verified/enabled (you might want to add an otp_enabled field)
        user.otp_expiry = None  # Clear any temporary expiry
        self._user_manager.update_user(user)
        
        return True
    
    async def verify_totp_setup_async(self, user_id: str, otp_code: str) -> bool:
        """Verify TOTP setup by validating the first OTP code (async)."""
        user = await self._user_manager.get_by_id_async(user_id)
        if not user:
            raise ValidationError("User not found")
        
        if not user.otp_secret:
            raise ValidationError("OTP not set up for this user")
        
        # Verify the OTP code
        if not self._security_utils.verify_totp(user.otp_secret, otp_code):
            raise OTPError("Invalid OTP code")
        
        # Mark OTP as verified/enabled
        user.otp_expiry = None  # Clear any temporary expiry
        await self._user_manager.update_user_async(user)
        
        return True
    
    def verify_otp(self, user_id: str, otp_code: str) -> bool:
        """
        Verify OTP code for a user.
        
        Args:
            user_id: ID of the user
            otp_code: OTP code to verify
            
        Returns:
            True if OTP is valid, False otherwise
        """
        try:
            user = self._user_manager.get_by_id(user_id)
            if not user or not user.otp_secret:
                return False
            
            # Check if it's a backup code first
            if self._is_backup_code(otp_code):
                return self._verify_backup_code(user_id, otp_code)
            
            # Verify TOTP code
            return self._security_utils.verify_totp(user.otp_secret, otp_code)
            
        except Exception as e:
            self._handle_auth_error(e, "OTP verification")
            return False
    
    async def verify_otp_async(self, user_id: str, otp_code: str) -> bool:
        """Verify OTP code for a user (async)."""
        try:
            user = await self._user_manager.get_by_id_async(user_id)
            if not user or not user.otp_secret:
                return False
            
            # Check if it's a backup code first
            if self._is_backup_code(otp_code):
                return await self._verify_backup_code_async(user_id, otp_code)
            
            # Verify TOTP code
            return self._security_utils.verify_totp(user.otp_secret, otp_code)
            
        except Exception as e:
            self._handle_auth_error(e, "OTP verification (async)")
            return False
    
    def authenticate(self, credentials: Dict[str, Any], set_cookies: bool = False) -> Dict[str, Any]:
        """
        Authenticate user with OTP code (used as second factor).
        
        Args:
            credentials: Dict with 'user_id' and 'otp_code'
            set_cookies: Whether to set HTTP cookies for tokens
            
        Returns:
            Authentication result with user and tokens
            
        Raises:
            ValidationError: If required fields missing
            InvalidCredentialsError: If OTP is invalid
        """
        self._validate_required_fields(credentials, ['user_id', 'otp_code'])
        
        user_id = credentials.get("user_id")
        otp_code = credentials.get("otp_code")
        
        # Verify OTP
        if not self.verify_otp(user_id, otp_code):
            raise InvalidCredentialsError("Invalid OTP code")
        
        # Get user
        user = self._user_manager.get_by_id(user_id)
        if not user:
            raise InvalidCredentialsError("User not found")
        
        # Generate tokens
        tokens = self._token_manager.generate_token_pair(user.id)
        
        response_dict = self._format_auth_response(
            user, tokens["access"].token, tokens["refresh"].token,
            {"auth_method": "otp"}
        )
        
        if set_cookies:
            return self._create_cookie_response(
                response_dict, tokens["access"].token, tokens["refresh"].token
            )
        
        return response_dict
    
    async def authenticate_async(self, credentials: Dict[str, Any], set_cookies: bool = False) -> Dict[str, Any]:
        """Authenticate user with OTP code (async)."""
        self._validate_required_fields(credentials, ['user_id', 'otp_code'])
        
        user_id = credentials.get("user_id")
        otp_code = credentials.get("otp_code")
        
        # Verify OTP
        if not await self.verify_otp_async(user_id, otp_code):
            raise InvalidCredentialsError("Invalid OTP code")
        
        # Get user
        user = await self._user_manager.get_by_id_async(user_id)
        if not user:
            raise InvalidCredentialsError("User not found")
        
        # Generate tokens
        tokens = await self._token_manager.generate_token_pair_async(user.id)
        
        response_dict = self._format_auth_response(
            user, tokens["access"].token, tokens["refresh"].token,
            {"auth_method": "otp"}
        )
        
        if set_cookies:
            return self._create_cookie_response(
                response_dict, tokens["access"].token, tokens["refresh"].token
            )
        
        return response_dict
    
    def register(self, user_data: Dict[str, Any]) -> User:
        """OTP service doesn't handle user registration directly."""
        raise NotImplementedError("OTP service doesn't handle user registration")
    
    async def register_async(self, user_data: Dict[str, Any]) -> User:
        """OTP service doesn't handle user registration directly (async)."""
        raise NotImplementedError("OTP service doesn't handle user registration")
    
    def disable_otp(self, user_id: str) -> bool:
        """
        Disable OTP for a user.
        
        Args:
            user_id: ID of the user
            
        Returns:
            True if OTP was disabled successfully
        """
        user = self._user_manager.get_by_id(user_id)
        if not user:
            return False
        
        # Clear OTP secret and related data
        user.otp_secret = None
        user.otp_expiry = None
        self._user_manager.update_user(user)
        
        return True
    
    async def disable_otp_async(self, user_id: str) -> bool:
        """Disable OTP for a user (async)."""
        user = await self._user_manager.get_by_id_async(user_id)
        if not user:
            return False
        
        # Clear OTP secret and related data
        user.otp_secret = None
        user.otp_expiry = None
        await self._user_manager.update_user_async(user)
        
        return True
    
    def get_otp_status(self, user_id: str) -> Dict[str, Any]:
        """
        Get OTP status for a user.
        
        Args:
            user_id: ID of the user
            
        Returns:
            Dict with OTP status information
        """
        user = self._user_manager.get_by_id(user_id)
        if not user:
            return {"enabled": False, "configured": False}
        
        return {
            "enabled": bool(user.otp_secret),
            "configured": bool(user.otp_secret),
            "issuer": config.OTP_ISSUER
        }
    
    async def get_otp_status_async(self, user_id: str) -> Dict[str, Any]:
        """Get OTP status for a user (async)."""
        user = await self._user_manager.get_by_id_async(user_id)
        if not user:
            return {"enabled": False, "configured": False}
        
        return {
            "enabled": bool(user.otp_secret),
            "configured": bool(user.otp_secret),
            "issuer": config.OTP_ISSUER
        }
    
    def regenerate_backup_codes(self, user_id: str) -> list[str]:
        """
        Regenerate backup codes for a user.
        
        Args:
            user_id: ID of the user
            
        Returns:
            List of new backup codes
        """
        user = self._user_manager.get_by_id(user_id)
        if not user:
            raise ValidationError("User not found")
        
        # Generate new backup codes
        backup_codes = self._generate_backup_codes()
        
        # In a real implementation, you'd store these securely
        # For now, we'll return them to be stored by the caller
        
        return backup_codes
    
    async def regenerate_backup_codes_async(self, user_id: str) -> list[str]:
        """Regenerate backup codes for a user (async)."""
        user = await self._user_manager.get_by_id_async(user_id)
        if not user:
            raise ValidationError("User not found")
        
        # Generate new backup codes
        backup_codes = self._generate_backup_codes()
        
        return backup_codes
    
    # Private helper methods
    def _generate_qr_code(self, totp_uri: str) -> str:
        """Generate QR code as base64 encoded PNG."""
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        # Create QR code image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        img_str = base64.b64encode(buffer.getvalue()).decode()
        
        return f"data:image/png;base64,{img_str}"
    
    def _generate_backup_codes(self, count: int = 10) -> list[str]:
        """Generate backup codes for OTP recovery."""
        backup_codes = []
        for _ in range(count):
            # Generate 8-character alphanumeric codes
            code = self._security_utils.generate_secure_token(4)[:8].upper()
            backup_codes.append(code)
        return backup_codes
    
    def _is_backup_code(self, code: str) -> bool:
        """Check if the provided code looks like a backup code."""
        # Backup codes are typically 8 characters, alphanumeric
        return len(code) == 8 and code.isalnum()
    
    def _verify_backup_code(self, user_id: str, backup_code: str) -> bool:
        """Verify backup code (placeholder - needs proper implementation)."""
        # In a real implementation, you'd:
        # 1. Hash backup codes when storing them
        # 2. Check against stored hashed backup codes
        # 3. Mark used backup codes as consumed
        # 4. Store backup codes in a separate model/collection
        
        # For now, return False as backup codes aren't fully implemented
        return False
    
    async def _verify_backup_code_async(self, user_id: str, backup_code: str) -> bool:
        """Verify backup code (async, placeholder)."""
        return False
    
    def generate_recovery_codes(self, user_id: str) -> list[str]:
        """
        Generate one-time recovery codes for account recovery.
        
        Args:
            user_id: ID of the user
            
        Returns:
            List of recovery codes
        """
        user = self._user_manager.get_by_id(user_id)
        if not user:
            raise ValidationError("User not found")
        
        # Generate recovery codes (longer than backup codes)
        recovery_codes = []
        for _ in range(5):  # Fewer recovery codes, but more secure
            code = self._security_utils.generate_secure_token(8)[:16].upper()
            recovery_codes.append(code)
        
        return recovery_codes
    
    async def generate_recovery_codes_async(self, user_id: str) -> list[str]:
        """Generate recovery codes (async)."""
        user = await self._user_manager.get_by_id_async(user_id)
        if not user:
            raise ValidationError("User not found")
        
        # Generate recovery codes
        recovery_codes = []
        for _ in range(5):
            code = self._security_utils.generate_secure_token(8)[:16].upper()
            recovery_codes.append(code)
        
        return recovery_codes
