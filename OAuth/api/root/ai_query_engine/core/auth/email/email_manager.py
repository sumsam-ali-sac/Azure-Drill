"""
Email management functionality.
Handles SMTP configuration and email sending operations.
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional

from auth.configs import config
from auth.constants import EMAIL_TEMPLATE_PASSWORD_RESET, EMAIL_TEMPLATE_WELCOME
from auth.exceptions import EmailSendError


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
