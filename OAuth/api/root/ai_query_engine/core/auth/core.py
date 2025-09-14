"""
Core authentication manager that orchestrates all authentication flows.
Provides high-level methods for login, registration, password reset, and OAuth.
"""

import asyncio
from typing import Dict, Any, Optional, Tuple, List
from datetime import datetime, timezone
from fastapi import Request, Response
from .configs import config
from .constants import (
    TOKEN_TYPE_ACCESS,
    TOKEN_TYPE_REFRESH,
    SUCCESS_LOGIN,
    SUCCESS_REGISTRATION,
    SUCCESS_PASSWORD_RESET,
    SUCCESS_OTP_SENT,
    SUCCESS_TOKEN_REFRESHED
)
from .exceptions import (
    InvalidCredentialsError,
    OTPInvalidError,
    TokenExpiredError,
    TokenInvalidError,
    EmailAlreadyExistsError,
    UserNotFoundError,
    WeakPasswordError,
    RateLimitExceededError,
    OAuthError
)
from .schemas import (
    UserRegistration,
    UserLogin,
    TokenResponse,
    PasswordResetRequest,
    PasswordReset,
    OTPRequest,
    UserProfile,
    SocialLoginRequest
)
from .password_utils import password_manager, password_policy
from .otp_utils import otp_manager
from .token_utils import token_manager
from .oauth_utils import oauth_manager
from .session_utils import token_cookie_manager, session_manager
from .utils import email_manager, rate_limiter, security_utils
from .validators import input_validator


class AuthManager:
    """
    Core authentication manager that orchestrates all authentication flows.
    Provides a unified interface for all authentication operations.
    """
    
    def __init__(self):
        self.user_store: Dict[str, Dict[str, Any]] = {}  # Use database in production
        self.failed_attempts: Dict[str, List[datetime]] = {}  # Use Redis in production
    
    # User Management Methods
    
    def _get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Get user by email from storage."""
        email = security_utils.sanitize_email(email)
        return self.user_store.get(email)
    
    def _create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new user in storage."""
        email = security_utils.sanitize_email(user_data['email'])
        user_id = security_utils.generate_secure_token(16)
        
        user = {
            'id': user_id,
            'email': email,
            'password_hash': user_data.get('password_hash'),
            'first_name': user_data.get('first_name'),
            'last_name': user_data.get('last_name'),
            'roles': user_data.get('roles', ['user']),
            'is_active': True,
            'is_verified': user_data.get('is_verified', False),
            'created_at': datetime.now(timezone.utc),
            'last_login': None,
            'oauth_providers': user_data.get('oauth_providers', []),
            'failed_login_attempts': 0,
            'locked_until': None
        }
        
        self.user_store[email] = user
        return user
    
    def _update_user(self, email: str, updates: Dict[str, Any]) -> bool:
        """Update user data in storage."""
        email = security_utils.sanitize_email(email)
        if email in self.user_store:
            self.user_store[email].update(updates)
            return True
        return False
    
    def _is_account_locked(self, email: str) -> bool:
        """Check if account is locked due to failed attempts."""
        user = self._get_user_by_email(email)
        if not user:
            return False
        
        locked_until = user.get('locked_until')
        if locked_until and datetime.now(timezone.utc) < locked_until:
            return True
        
        return False
    
    def _record_failed_attempt(self, email: str):
        """Record failed login attempt."""
        user = self._get_user_by_email(email)
        if user:
            attempts = user.get('failed_login_attempts', 0) + 1
            self._update_user(email, {'failed_login_attempts': attempts})
            
            # Lock account after 5 failed attempts
            if attempts >= 5:
                from datetime import timedelta
                locked_until = datetime.now(timezone.utc) + timedelta(minutes=30)
                self._update_user(email, {'locked_until': locked_until})
    
    def _clear_failed_attempts(self, email: str):
        """Clear failed login attempts after successful login."""
        self._update_user(email, {
            'failed_login_attempts': 0,
            'locked_until': None,
            'last_login': datetime.now(timezone.utc)
        })
    
    # Registration Methods
    
    @rate_limiter.limit("register", 5, 300)  # 5 attempts per 5 minutes
    def register_user(self, registration_data: UserRegistration) -> Dict[str, Any]:
        """
        Register a new user with email and password.
        
        Args:
            registration_data: User registration information
        
        Returns:
            Registration result with user information
        
        Raises:
            EmailAlreadyExistsError: If email is already registered
            WeakPasswordError: If password doesn't meet requirements
        """
        # Validate input
        validation_result = input_validator.validate_user_registration(registration_data.dict())
        if not validation_result['valid']:
            raise WeakPasswordError(str(validation_result['errors']))
        
        email = security_utils.sanitize_email(registration_data.email)
        
        # Check if user already exists
        if self._get_user_by_email(email):
            raise EmailAlreadyExistsError()
        
        # Hash password
        password_hash = password_manager.hash_password(registration_data.password)
        
        # Create user
        user_data = {
            'email': email,
            'password_hash': password_hash,
            'first_name': registration_data.first_name,
            'last_name': registration_data.last_name,
            'roles': registration_data.roles,
            'is_verified': False  # Require email verification
        }
        
        user = self._create_user(user_data)
        
        # Send welcome email (async in production)
        try:
            user_name = user.get('first_name') or email
            email_manager.send_welcome_email(email, user_name)
        except Exception:
            # Don't fail registration if email fails
            pass
        
        return {
            'success': True,
            'message': SUCCESS_REGISTRATION,
            'user': self._format_user_profile(user),
            'requires_verification': True
        }
    
    # Login Methods
    
    @rate_limiter.limit("login", config.RATE_LIMIT_LOGIN_PER_MIN, 60)
    def login_with_password(
        self,
        login_data: UserLogin,
        request: Optional[Request] = None
    ) -> Dict[str, Any]:
        """
        Authenticate user with email and password.
        
        Args:
            login_data: Login credentials
            request: Optional FastAPI request object
        
        Returns:
            Authentication result with tokens
        
        Raises:
            InvalidCredentialsError: If credentials are invalid
            OTPInvalidError: If OTP is required but invalid
        """
        email = security_utils.sanitize_email(login_data.email)
        
        # Check if account is locked
        if self._is_account_locked(email):
            raise InvalidCredentialsError("Account is temporarily locked due to failed attempts")
        
        # Get user
        user = self._get_user_by_email(email)
        if not user or not user.get('password_hash'):
            self._record_failed_attempt(email)
            raise InvalidCredentialsError()
        
        # Verify password
        if not password_manager.verify_password(login_data.password, user['password_hash']):
            self._record_failed_attempt(email)
            raise InvalidCredentialsError()
        
        # Check if OTP is required
        if config.REQUIRE_OTP:
            if not login_data.otp_code:
                # Send OTP and return partial success
                otp_manager.send_otp_email(email, user['id'], "login")
                return {
                    'success': False,
                    'message': SUCCESS_OTP_SENT,
                    'requires_otp': True,
                    'otp_status': otp_manager.get_otp_status(user['id'])
                }
            else:
                # Verify OTP
                if not otp_manager.verify_otp_code(user['id'], login_data.otp_code):
                    raise OTPInvalidError()
        
        # Clear failed attempts
        self._clear_failed_attempts(email)
        
        # Create tokens
        tokens = self._create_user_tokens(user)
        
        return {
            'success': True,
            'message': SUCCESS_LOGIN,
            'tokens': tokens,
            'user': self._format_user_profile(user)
        }
    
    def send_otp_code(self, otp_request: OTPRequest) -> Dict[str, Any]:
        """
        Send OTP code to user's email.
        
        Args:
            otp_request: OTP request information
        
        Returns:
            OTP send result
        """
        email = security_utils.sanitize_email(otp_request.email)
        user = self._get_user_by_email(email)
        
        if not user:
            raise UserNotFoundError()
        
        # Send OTP
        otp_manager.send_otp_email(email, user['id'], otp_request.action)
        
        return {
            'success': True,
            'message': SUCCESS_OTP_SENT,
            'otp_status': otp_manager.get_otp_status(user['id'])
        }
    
    # OAuth Methods
    
    def get_oauth_authorization_url(
        self,
        social_request: SocialLoginRequest,
        request: Request
    ) -> Dict[str, Any]:
        """
        Get OAuth authorization URL for social login.
        
        Args:
            social_request: Social login request
            request: FastAPI request object
        
        Returns:
            Authorization URL and state
        """
        redirect_uri = f"{config.BACKEND_URL}/auth/oauth/{social_request.provider}/callback"
        
        auth_url, state = oauth_manager.get_authorization_url(
            social_request.provider,
            redirect_uri,
            user_redirect=social_request.redirect_uri
        )
        
        return {
            'success': True,
            'authorization_url': auth_url,
            'state': state,
            'provider': social_request.provider
        }
    
    async def handle_oauth_callback(
        self,
        provider: str,
        code: str,
        state: str,
        request: Request
    ) -> Dict[str, Any]:
        """
        Handle OAuth callback and authenticate user.
        
        Args:
            provider: OAuth provider name
            code: Authorization code
            state: State parameter
            request: FastAPI request object
        
        Returns:
            Authentication result
        """
        try:
            redirect_uri = f"{config.BACKEND_URL}/auth/oauth/{provider}/callback"
            
            # Handle OAuth callback
            oauth_result = oauth_manager.handle_oauth_callback(
                provider, code, state, redirect_uri
            )
            
            user_info = oauth_result['user_info']
            email = security_utils.sanitize_email(user_info['email'])
            
            # Check if user exists
            user = self._get_user_by_email(email)
            
            if not user:
                # Create new user from OAuth data
                user_data = {
                    'email': email,
                    'first_name': user_info.get('first_name'),
                    'last_name': user_info.get('last_name'),
                    'roles': ['user'],
                    'is_verified': user_info.get('verified_email', True),
                    'oauth_providers': [provider]
                }
                user = self._create_user(user_data)
            else:
                # Update OAuth providers
                oauth_providers = user.get('oauth_providers', [])
                if provider not in oauth_providers:
                    oauth_providers.append(provider)
                    self._update_user(email, {'oauth_providers': oauth_providers})
            
            # Create tokens
            tokens = self._create_user_tokens(user)
            
            return {
                'success': True,
                'message': SUCCESS_LOGIN,
                'tokens': tokens,
                'user': self._format_user_profile(user),
                'oauth_data': oauth_result
            }
            
        except Exception as e:
            raise OAuthError(f"OAuth authentication failed: {str(e)}", provider)
    
    # Token Management Methods
    
    def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """
        Refresh access token using refresh token.
        
        Args:
            refresh_token: Valid refresh token
        
        Returns:
            New access token
        """
        try:
            # Verify refresh token
            payload = token_manager.verify_token(refresh_token, token_type=TOKEN_TYPE_REFRESH)
            
            # Get user to ensure they still exist and are active
            email = payload.get('email')
            user = self._get_user_by_email(email)
            
            if not user or not user.get('is_active'):
                raise TokenInvalidError("User not found or inactive")
            
            # Create new access token
            new_access_token = token_manager.create_token(
                {
                    'sub': user['email'],
                    'email': user['email'],
                    'roles': user['roles'],
                    'user_id': user['id']
                },
                expires_minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES,
                token_type=TOKEN_TYPE_ACCESS
            )
            
            return {
                'success': True,
                'message': SUCCESS_TOKEN_REFRESHED,
                'access_token': new_access_token,
                'token_type': 'bearer',
                'expires_in': config.ACCESS_TOKEN_EXPIRE_MINUTES * 60
            }
            
        except (TokenExpiredError, TokenInvalidError) as e:
            raise TokenInvalidError("Invalid or expired refresh token")
    
    # Password Management Methods
    
    @rate_limiter.limit("password_reset", config.RATE_LIMIT_RESET_PER_HOUR, 3600)
    def request_password_reset(self, reset_request: PasswordResetRequest) -> Dict[str, Any]:
        """
        Request password reset for user.
        
        Args:
            reset_request: Password reset request
        
        Returns:
            Reset request result
        """
        email = security_utils.sanitize_email(reset_request.email)
        user = self._get_user_by_email(email)
        
        # Always return success to prevent email enumeration
        if user:
            # Generate reset token
            reset_token = password_manager.create_password_reset_token(email)
            
            # Send reset email
            try:
                email_manager.send_password_reset_email(email, reset_token)
            except Exception:
                # Don't fail if email sending fails
                pass
        
        return {
            'success': True,
            'message': 'If the email exists, a password reset link has been sent'
        }
    
    def reset_password(self, reset_data: PasswordReset) -> Dict[str, Any]:
        """
        Reset user password using reset token.
        
        Args:
            reset_data: Password reset data
        
        Returns:
            Reset result
        """
        try:
            # Verify reset token
            email = password_manager.verify_password_reset_token(reset_data.token)
            user = self._get_user_by_email(email)
            
            if not user:
                raise UserNotFoundError()
            
            # Hash new password
            new_password_hash = password_manager.hash_password(reset_data.new_password)
            
            # Update user password
            self._update_user(email, {
                'password_hash': new_password_hash,
                'failed_login_attempts': 0,
                'locked_until': None
            })
            
            return {
                'success': True,
                'message': SUCCESS_PASSWORD_RESET
            }
            
        except (TokenExpiredError, TokenInvalidError):
            raise TokenInvalidError("Invalid or expired reset token")
    
    # Utility Methods
    
    def _create_user_tokens(self, user: Dict[str, Any]) -> TokenResponse:
        """Create JWT tokens for user."""
        payload = {
            'sub': user['email'],
            'email': user['email'],
            'roles': user['roles'],
            'user_id': user['id'],
            'first_name': user.get('first_name'),
            'last_name': user.get('last_name')
        }
        
        tokens = token_manager.create_token_pair(payload)
        
        return TokenResponse(
            access_token=tokens['access_token'],
            refresh_token=tokens['refresh_token'],
            token_type='bearer',
            expires_in=config.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            user_info=self._format_user_profile(user)
        )
    
    def _format_user_profile(self, user: Dict[str, Any]) -> UserProfile:
        """Format user data as UserProfile."""
        return UserProfile(
            id=user['id'],
            email=user['email'],
            first_name=user.get('first_name'),
            last_name=user.get('last_name'),
            roles=user['roles'],
            is_active=user['is_active'],
            is_verified=user['is_verified'],
            created_at=user['created_at'],
            last_login=user.get('last_login'),
            oauth_providers=user.get('oauth_providers', [])
        )
    
    def get_user_profile(self, user_id: str) -> Optional[UserProfile]:
        """Get user profile by ID."""
        for user in self.user_store.values():
            if user['id'] == user_id:
                return self._format_user_profile(user)
        return None
    
    def get_user_by_email(self, email: str) -> Optional[UserProfile]:
        """Get user profile by email."""
        user = self._get_user_by_email(email)
        if user:
            return self._format_user_profile(user)
        return None
    
    def verify_user_email(self, email: str) -> bool:
        """Mark user email as verified."""
        return self._update_user(email, {'is_verified': True})
    
    def deactivate_user(self, email: str) -> bool:
        """Deactivate user account."""
        return self._update_user(email, {'is_active': False})
    
    def activate_user(self, email: str) -> bool:
        """Activate user account."""
        return self._update_user(email, {'is_active': True})
    
    def change_user_password(
        self,
        email: str,
        current_password: str,
        new_password: str
    ) -> Dict[str, Any]:
        """
        Change user password (authenticated operation).
        
        Args:
            email: User email
            current_password: Current password
            new_password: New password
        
        Returns:
            Password change result
        """
        user = self._get_user_by_email(email)
        if not user:
            raise UserNotFoundError()
        
        # Verify current password
        if not password_manager.verify_password(current_password, user['password_hash']):
            raise InvalidCredentialsError("Current password is incorrect")
        
        # Hash new password
        new_password_hash = password_manager.hash_password(new_password)
        
        # Update password
        self._update_user(email, {'password_hash': new_password_hash})
        
        return {
            'success': True,
            'message': 'Password changed successfully'
        }
    
    def logout_user(self, request: Request, response: Response) -> Dict[str, Any]:
        """
        Logout user and clear session.
        
        Args:
            request: FastAPI request object
            response: FastAPI response object
        
        Returns:
            Logout result
        """
        # Clear cookies and session
        token_cookie_manager.clear_auth_cookies(response, request)
        
        # TODO: Add token to blacklist in production
        
        return {
            'success': True,
            'message': 'Logout successful'
        }
    
    def get_auth_status(self, token: str) -> Dict[str, Any]:
        """
        Get authentication status from token.
        
        Args:
            token: Access token
        
        Returns:
            Authentication status
        """
        try:
            payload = token_manager.verify_token(token, token_type=TOKEN_TYPE_ACCESS)
            user = self._get_user_by_email(payload.get('email'))
            
            if not user or not user.get('is_active'):
                return {'is_authenticated': False}
            
            return {
                'is_authenticated': True,
                'user': self._format_user_profile(user),
                'expires_at': datetime.fromtimestamp(payload.get('exp'), tz=timezone.utc)
            }
            
        except (TokenExpiredError, TokenInvalidError):
            return {'is_authenticated': False}


# Global auth manager instance
auth_manager = AuthManager()
