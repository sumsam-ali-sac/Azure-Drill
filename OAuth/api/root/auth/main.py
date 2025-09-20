"""
Main CLI module for testing authentication flows.
Optional command-line interface for testing the auth service.
"""

import asyncio
import sys
from typing import Dict, Any
from pymongo import MongoClient
from pymongo.database import Database

# Import auth service components
from auth.config import config
from auth.repositories.user_repository import UserRepository
from auth.repositories.token_repository import TokenRepository
from auth.repositories.otp_repository import OTPRepository
from auth.managers.user_manager import UserManager
from auth.managers.token_manager import TokenManager
from auth.managers.otp_manager import OTPManager
from auth.services.auth_service import AuthService
from auth.services.social_auth_service import SocialAuthService
from auth.services.otp_service import OTPService
from auth.providers.google import GoogleOAuthProvider
from auth.providers.azure import AzureOAuthProvider
from auth.utils.security import SecurityUtils
from auth.exceptions.auth_exceptions import AuthServiceError


class AuthServiceCLI:
    """Command-line interface for testing auth service functionality."""

    def __init__(self):
        """Initialize CLI with dependency injection."""
        # Initialize MongoDB connection
        self.mongo_client = MongoClient(config.MONGODB_URL)
        self.database: Database = self.mongo_client[config.DATABASE_NAME]

        # Initialize utilities
        self.security_utils = SecurityUtils()

        # Initialize repositories
        self.user_repository = UserRepository()
        self.user_repository._database = self.database  # Inject database

        self.token_repository = TokenRepository()
        self.token_repository._database = self.database  # Inject database

        self.otp_repository = OTPRepository()
        self.otp_repository._database = self.database  # Inject database

        # Initialize managers
        self.user_manager = UserManager(self.user_repository)
        self.token_manager = TokenManager(self.token_repository, self.security_utils)

        self.otp_manager = OTPManager(self.otp_repository)

        # Initialize providers
        try:
            self.google_provider = GoogleOAuthProvider()
        except Exception as e:
            print(f"Warning: Google OAuth not configured: {e}")
            self.google_provider = None

        try:
            self.azure_provider = AzureOAuthProvider()
        except Exception as e:
            print(f"Warning: Azure OAuth not configured: {e}")
            self.azure_provider = None

        # Initialize services
        self.auth_service = AuthService(
            self.user_manager, self.token_manager, self.security_utils
        )

        self.otp_service = OTPService(
            self.otp_manager, self.user_manager, self.security_utils
        )

        if self.google_provider and self.azure_provider:
            self.social_auth_service = SocialAuthService(
                self.user_manager,
                self.token_manager,
                self.google_provider,
                self.azure_provider,
            )
        else:
            self.social_auth_service = None

    def print_menu(self):
        """Print the main menu."""
        print("\n" + "=" * 50)
        print("AUTH SERVICE CLI")
        print("=" * 50)
        print("1. Register new user")
        print("2. Login with email/password")
        print("3. Change password")
        print("4. Reset password")
        print("5. Get Google OAuth URL")
        print("6. Get Azure OAuth URL")
        print("7. Validate token")
        print("8. List users")
        print("9. Cleanup expired tokens")
        print("10. Setup OTP for user")
        print("11. Verify OTP setup")
        print("12. Test OTP authentication")
        print("13. Generate backup codes")
        print("14. Disable OTP for user")
        print("15. Check OTP status")
        print("0. Exit")
        print("=" * 50)

    def register_user(self):
        """Register a new user."""
        print("\n--- User Registration ---")
        email = input("Email: ").strip()
        password = input("Password: ").strip()
        first_name = input("First Name (optional): ").strip() or None
        last_name = input("Last Name (optional): ").strip() or None

        try:
            user_data = {
                "email": email,
                "password": password,
                "first_name": first_name,
                "last_name": last_name,
            }

            user = self.auth.register(user_data)
            print(f"✅ User registered successfully!")
            print(f"   ID: {user.id}")
            print(f"   Email: {user.email}")
            print(f"   Name: {user.get_full_name()}")

        except AuthServiceError as e:
            print(f"❌ Registration failed: {e.message}")
        except Exception as e:
            print(f"❌ Unexpected error: {str(e)}")

    def login_user(self):
        """Login with email and password."""
        print("\n--- User Login ---")
        email = input("Email: ").strip()
        password = input("Password: ").strip()

        try:
            credentials = {"email": email, "password": password}

            result = self.auth.authenticate(credentials)
            user = result["user"]

            print(f"✅ Login successful!")
            print(f"   User: {user.get_full_name()} ({user.email})")
            print(f"   Access Token: {result['access_token'][:50]}...")
            print(f"   Refresh Token: {result['refresh_token'][:50]}...")

        except AuthServiceError as e:
            print(f"❌ Login failed: {e.message}")
        except Exception as e:
            print(f"❌ Unexpected error: {str(e)}")

    def change_password(self):
        """Change user password."""
        print("\n--- Change Password ---")
        email = input("Email: ").strip()
        old_password = input("Current Password: ").strip()
        new_password = input("New Password: ").strip()

        try:
            user = self.user_manager.get_user_by_email(email)

            success = self.auth.change_password(user.id, old_password, new_password)

            if success:
                print("✅ Password changed successfully!")
            else:
                print("❌ Password change failed")

        except AuthServiceError as e:
            print(f"❌ Password change failed: {e.message}")
        except Exception as e:
            print(f"❌ Unexpected error: {str(e)}")

    def reset_password(self):
        """Reset user password."""
        print("\n--- Password Reset ---")
        email = input("Email: ").strip()

        try:
            reset_token = self.auth.reset_password(email)
            print(f"✅ Password reset initiated!")
            print(f"   Reset Token: {reset_token[:50]}...")
            print("   (In production, this would be sent via email)")

            complete = input("\nComplete password reset? (y/n): ").strip().lower()
            if complete == "y":
                new_password = input("New Password: ").strip()
                success = self.auth.confirm_password_reset(reset_token, new_password)

                if success:
                    print("✅ Password reset completed!")
                else:
                    print("❌ Password reset failed")

        except AuthServiceError as e:
            print(f"❌ Password reset failed: {e.message}")
        except Exception as e:
            print(f"❌ Unexpected error: {str(e)}")

    def get_google_oauth_url(self):
        """Get Google OAuth authorization URL."""
        if not self.google_provider:
            print("❌ Google OAuth not configured")
            return

        print("\n--- Google OAuth ---")
        state = self.security_utils.generate_secure_token(16)

        try:
            auth_url = self.google_provider.get_auth_url(state)
            print(f"✅ Google OAuth URL generated!")
            print(f"   State: {state}")
            print(f"   URL: {auth_url}")
            print("\n   Open this URL in your browser to authorize the application.")

        except Exception as e:
            print(f"❌ Failed to generate Google OAuth URL: {str(e)}")

    def get_azure_oauth_url(self):
        """Get Azure OAuth authorization URL."""
        if not self.azure_provider:
            print("❌ Azure OAuth not configured")
            return

        print("\n--- Azure OAuth ---")
        state = self.security_utils.generate_secure_token(16)

        try:
            auth_url = self.azure_provider.get_auth_url(state)
            print(f"✅ Azure OAuth URL generated!")
            print(f"   State: {state}")
            print(f"   URL: {auth_url}")
            print("\n   Open this URL in your browser to authorize the application.")

        except Exception as e:
            print(f"❌ Failed to generate Azure OAuth URL: {str(e)}")

    def validate_token(self):
        """Validate a JWT token."""
        print("\n--- Token Validation ---")
        token = input("JWT Token: ").strip()

        try:
            payload = self.token_manager.validate_token(token)
            print(f"✅ Token is valid!")
            print(f"   User ID: {payload.get('user_id')}")
            print(f"   Token Type: {payload.get('token_type')}")
            print(f"   Expires: {payload.get('exp')}")

        except AuthServiceError as e:
            print(f"❌ Token validation failed: {e.message}")
        except Exception as e:
            print(f"❌ Unexpected error: {str(e)}")

    def list_users(self):
        """List all users."""
        print("\n--- User List ---")

        try:
            users = self.user_repository.get_active_users(limit=10)

            if not users:
                print("No users found.")
                return

            print(f"Found {len(users)} users:")
            for i, user in enumerate(users, 1):
                print(f"   {i}. {user.get_full_name()} ({user.email})")
                print(f"      ID: {user.id}")
                print(f"      Active: {user.is_active}")
                print(f"      Social Providers: {list(user.social_ids.keys())}")
                print(f"      Created: {user.created_on}")
                print()

        except Exception as e:
            print(f"❌ Failed to list users: {str(e)}")

    def cleanup_expired_tokens(self):
        """Clean up expired tokens."""
        print("\n--- Token Cleanup ---")

        try:
            count = self.token_manager.cleanup_expired_tokens()
            print(f"✅ Cleaned up {count} expired tokens")

        except Exception as e:
            print(f"❌ Token cleanup failed: {str(e)}")

    def setup_otp(self):
        """Setup OTP for a user."""
        print("\n--- OTP Setup ---")
        email = input("User Email: ").strip()

        try:
            user = self.user_manager.get_user_by_email(email)
            if not user:
                print("❌ User not found")
                return

            result = self.otp_service.setup_totp(user.id)

            print("✅ OTP Setup initiated!")
            print(f"   Secret: {result['secret']}")
            print(f"   QR Code URL: {result['qr_code_url']}")
            print(f"   Backup Codes: {', '.join(result['backup_codes'])}")
            print("\n   Scan the QR code with your authenticator app.")

        except AuthServiceError as e:
            print(f"❌ OTP setup failed: {e.message}")
        except Exception as e:
            print(f"❌ Unexpected error: {str(e)}")

    def verify_otp_setup(self):
        """Verify OTP setup completion."""
        print("\n--- Verify OTP Setup ---")
        email = input("User Email: ").strip()
        otp_code = input("OTP Code from app: ").strip()

        try:
            user = self.user_manager.get_user_by_email(email)
            if not user:
                print("❌ User not found")
                return

            success = self.otp_service.verify_setup(user.id, otp_code)

            if success:
                print("✅ OTP setup verified successfully!")
                print("   Two-factor authentication is now enabled.")
            else:
                print("❌ OTP verification failed")

        except AuthServiceError as e:
            print(f"❌ OTP verification failed: {e.message}")
        except Exception as e:
            print(f"❌ Unexpected error: {str(e)}")

    def test_otp_auth(self):
        """Test OTP authentication."""
        print("\n--- Test OTP Authentication ---")
        email = input("User Email: ").strip()
        otp_code = input("OTP Code: ").strip()

        try:
            user = self.user_manager.get_user_by_email(email)
            if not user:
                print("❌ User not found")
                return

            is_valid = self.otp_service.verify_otp(user.id, otp_code)

            if is_valid:
                print("✅ OTP authentication successful!")
            else:
                print("❌ OTP authentication failed")

        except AuthServiceError as e:
            print(f"❌ OTP authentication failed: {e.message}")
        except Exception as e:
            print(f"❌ Unexpected error: {str(e)}")

    def generate_backup_codes(self):
        """Generate new backup codes for user."""
        print("\n--- Generate Backup Codes ---")
        email = input("User Email: ").strip()

        try:
            user = self.user_manager.get_user_by_email(email)
            if not user:
                print("❌ User not found")
                return

            backup_codes = self.otp_service.generate_backup_codes(user.id)

            print("✅ New backup codes generated!")
            print("   Backup Codes:")
            for i, code in enumerate(backup_codes, 1):
                print(f"   {i}. {code}")
            print("\n   Store these codes in a safe place.")

        except AuthServiceError as e:
            print(f"❌ Backup code generation failed: {e.message}")
        except Exception as e:
            print(f"❌ Unexpected error: {str(e)}")

    def disable_otp(self):
        """Disable OTP for a user."""
        print("\n--- Disable OTP ---")
        email = input("User Email: ").strip()

        try:
            user = self.user_manager.get_user_by_email(email)
            if not user:
                print("❌ User not found")
                return

            success = self.otp_service.disable_otp(user.id)

            if success:
                print("✅ OTP disabled successfully!")
            else:
                print("❌ OTP disable failed (may not be enabled)")

        except AuthServiceError as e:
            print(f"❌ OTP disable failed: {e.message}")
        except Exception as e:
            print(f"❌ Unexpected error: {str(e)}")

    def check_otp_status(self):
        """Check OTP status for a user."""
        print("\n--- OTP Status ---")
        email = input("User Email: ").strip()

        try:
            user = self.user_manager.get_user_by_email(email)
            if not user:
                print("❌ User not found")
                return

            status = self.otp_service.get_otp_status(user.id)

            print(f"✅ OTP Status for {user.email}:")
            print(f"   Enabled: {status['enabled']}")
            print(f"   Verified: {status['verified']}")
            if status["enabled"]:
                print(f"   Backup Codes Available: {status['backup_codes_count']}")

        except AuthServiceError as e:
            print(f"❌ OTP status check failed: {e.message}")
        except Exception as e:
            print(f"❌ Unexpected error: {str(e)}")

    def run(self):
        """Run the CLI application."""
        print("Welcome to Auth Service CLI!")
        print(f"Connected to MongoDB: {config.MONGODB_URL}")
        print(f"Database: {config.DATABASE_NAME}")

        while True:
            try:
                self.print_menu()
                choice = input("\nEnter your choice (0-15): ").strip()

                if choice == "0":
                    print("Goodbye!")
                    break
                elif choice == "1":
                    self.register_user()
                elif choice == "2":
                    self.login_user()
                elif choice == "3":
                    self.change_password()
                elif choice == "4":
                    self.reset_password()
                elif choice == "5":
                    self.get_google_oauth_url()
                elif choice == "6":
                    self.get_azure_oauth_url()
                elif choice == "7":
                    self.validate_token()
                elif choice == "8":
                    self.list_users()
                elif choice == "9":
                    self.cleanup_expired_tokens()
                elif choice == "10":
                    self.setup_otp()
                elif choice == "11":
                    self.verify_otp_setup()
                elif choice == "12":
                    self.test_otp_auth()
                elif choice == "13":
                    self.generate_backup_codes()
                elif choice == "14":
                    self.disable_otp()
                elif choice == "15":
                    self.check_otp_status()
                else:
                    print("❌ Invalid choice. Please try again.")

                input("\nPress Enter to continue...")

            except KeyboardInterrupt:
                print("\n\nGoodbye!")
                break
            except Exception as e:
                print(f"❌ Unexpected error: {str(e)}")
                input("\nPress Enter to continue...")

    def __del__(self):
        """Clean up MongoDB connection."""
        if hasattr(self, "mongo_client"):
            self.mongo_client.close()


def main():
    """Main entry point for CLI."""
    try:
        cli = AuthServiceCLI()
        cli.run()
    except Exception as e:
        print(f"Failed to start CLI: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
