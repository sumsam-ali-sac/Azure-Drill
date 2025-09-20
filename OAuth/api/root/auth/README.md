# Authentication Service

A comprehensive, modular, and secure authentication service built with Python and FastAPI. Supports multiple authentication methods including email/password, social sign-ins (Google, Azure with MSAL), and two-factor authentication with OTP/TOTP.

## 🏗️ Architecture Overview

The service follows a clean, layered architecture with dependency injection:

\`\`\`
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ API Routes │ │ CLI Commands │ │ Web Interface │
├─────────────────┤ ├─────────────────┤ ├─────────────────┤
│ FastAPI Routes │ │ Click Commands │ │ Optional Frontend│
└─────────────────┘ └─────────────────┘ └─────────────────┘
│ │ │
└───────────────────────┼───────────────────────┘
│
┌─────────────────────────────────┼─────────────────────────────────┐
│ Services Layer │
├─────────────────┬───────────────┬───────────────┬─────────────────┤
│ AuthService │ SocialAuth │ OTPService │ TokenService │
│ (Email/Pass) │ Service │ (TOTP) │ (JWT Mgmt) │
└─────────────────┴───────────────┴───────────────┴─────────────────┘
│ │ │
┌─────────────────────────────────┼─────────────────────────────────┐
│ Managers Layer │
├─────────────────┬───────────────┬───────────────┬─────────────────┤
│ UserManager │ TokenManager │ OTPManager │ SessionManager │
│ (User Logic) │ (JWT Logic) │ (OTP Logic) │ (Session Logic) │
└─────────────────┴───────────────┴───────────────┴─────────────────┘
│ │ │
┌─────────────────────────────────┼─────────────────────────────────┐
│ Repositories Layer │
├─────────────────┬───────────────┬───────────────┬─────────────────┤
│ UserRepository │TokenRepository│ OTPRepository │SessionRepository│
│ (User Data) │ (Token Data) │ (OTP Data) │ (Session Data) │
└─────────────────┴───────────────┴───────────────┴─────────────────┘
│ │ │
┌─────────────────────────────────┼─────────────────────────────────┐
│ Database Layer │
├─────────────────────────────────┼─────────────────────────────────┤
│ MongoDB │
│ Collections: users, tokens, otp_codes, sessions │
└─────────────────────────────────────────────────────────────────────┘
\`\`\`

### 🔄 Authentication Flow Diagrams

#### Email/Password Authentication Flow

\`\`\`
┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐
│ Client │ │ API │ │ Service │ │Manager │ │Database │
└────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘
│ │ │ │ │
│ POST /login │ │ │ │
├─────────────►│ │ │ │
│ │ authenticate │ │ │
│ ├─────────────►│ │ │
│ │ │ get_user_by │ │
│ │ │ \_email │ │
│ │ ├─────────────►│ │
│ │ │ │ find_user │
│ │ │ ├─────────────►│
│ │ │ │ user_data │
│ │ │ │◄─────────────┤
│ │ │ user_object │ │
│ │ │◄─────────────┤ │
│ │ verify_pass │ │ │
│ │ generate_jwt │ │ │
│ │◄─────────────┤ │ │
│ JWT tokens │ │ │ │
│◄─────────────┤ │ │ │
\`\`\`

#### Social OAuth Flow (Google/Azure)

\`\`\`
┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐
│ Client │ │ API │ │ Service │ │Provider │ │OAuth │ │Database │
└────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘
│ │ │ │ │ │
│GET /auth │ │ │ │ │
│ /google │ │ │ │ │
├───────────►│ │ │ │ │
│ │get*auth_url│ │ │ │
│ ├───────────►│ │ │ │
│ │ │build_oauth │ │ │
│ │ │ \_url │ │ │
│ │ ├───────────►│ │ │
│ │ │ oauth_url │ │ │
│ │ │◄───────────┤ │ │
│ oauth_url │ │ │ │ │
│◄───────────┤ │ │ │ │
│ │ │ │ │ │
│ [User redirected to OAuth provider] │ │ │
├──────────────────────────────────────┼───────────►│ │
│ │ │ │ │ [User │
│ │ │ │ │ consents] │
│ │ │ │ │ │
│ [Callback with auth code] │ │ │
│◄──────────────────────────────────────────────────┤ │
│ │ │ │ │ │
│POST /auth │ │ │ │ │
│ /callback │ │ │ │ │
├───────────►│ │ │ │ │
│ │authenticate│ │ │ │
│ ├───────────►│ │ │ │
│ │ │exchange* │ │ │
│ │ │ code │ │ │
│ │ ├───────────►│ │ │
│ │ │ │token*req │ │
│ │ │ ├───────────►│ │
│ │ │ │tokens │ │
│ │ │ │◄───────────┤ │
│ │ │ tokens │ │ │
│ │ │◄───────────┤ │ │
│ │ │get_user* │ │ │
│ │ │ info │ │ │
│ │ ├───────────►│ │ │
│ │ │ │user*req │ │
│ │ │ ├───────────►│ │
│ │ │ │user_data │ │
│ │ │ │◄───────────┤ │
│ │ │ user_data │ │ │
│ │ │◄───────────┤ │ │
│ │ │create_or* │ │ │
│ │ │update_user │ │ │
│ │ ├────────────┼────────────┼───────────►│
│ │ │ │ │ │
│ JWT tokens │ │ │ │ │
│◄───────────┤ │ │ │ │
\`\`\`

#### OTP/TOTP Setup and Verification Flow

\`\`\`
┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐
│ Client │ │ API │ │ Service │ │Manager │ │Database │
└────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘
│ │ │ │ │
│POST /otp/ │ │ │ │
│ setup │ │ │ │
├─────────────►│ │ │ │
│ │ setup*otp │ │ │
│ ├─────────────►│ │ │
│ │ │generate* │ │
│ │ │ secret │ │
│ │ ├─────────────►│ │
│ │ │ │store_secret │
│ │ │ ├─────────────►│
│ │ │ │ │
│ │ │generate_qr │ │
│ │ │ │ │
│ │ secret+qr │ │ │
│ │◄─────────────┤ │ │
│ QR code + │ │ │ │
│ backup codes │ │ │ │
│◄─────────────┤ │ │ │
│ │ │ │ │
│ [User scans QR with authenticator app] │ │
│ │ │ │ │
│POST /otp/ │ │ │ │
│ verify │ │ │ │
├─────────────►│ │ │ │
│ │ verify_otp │ │ │
│ ├─────────────►│ │ │
│ │ │validate_totp │ │
│ │ ├─────────────►│ │
│ │ │ │check_code │
│ │ │ ├─────────────►│
│ │ │ │ valid │
│ │ │ │◄─────────────┤
│ │ │ success │ │
│ │ │◄─────────────┤ │
│ │ otp_enabled │ │ │
│ │◄─────────────┤ │ │
│ success │ │ │ │
│◄─────────────┤ │ │ │
\`\`\`

## 🚀 Quick Start

### Prerequisites

-   Python 3.8+
-   MongoDB 4.4+
-   OAuth provider credentials (Google, Azure)

### Installation

1. **Clone and install dependencies:**
   \`\`\`bash
   git clone <repository-url>
   cd auth-service
   pip install -r requirements.txt
   \`\`\`

2. **Environment setup:**
   \`\`\`bash
   cp .env.example .env

# Edit .env with your configuration

\`\`\`

3. **Required environment variables:**
   \`\`\`bash

# Database

MONGODB_URL=mongodb://localhost:27017/auth_service

# JWT Configuration

JWT_SECRET=your-super-secret-jwt-key-256-bits-minimum
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

# Google OAuth

GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:8000/auth/google/callback

# Azure OAuth (using MSAL)

AZURE_CLIENT_ID=your-azure-client-id
AZURE_CLIENT_SECRET=your-azure-client-secret
AZURE_TENANT_ID=your-azure-tenant-id
AZURE_REDIRECT_URI=http://localhost:8000/auth/azure/callback

# Security Settings

COOKIE_SECURE=false # Set to true in production
COOKIE_SAMESITE=lax
COOKIE_DOMAIN=localhost
COOKIE_PATH=/

# Password Policy

MIN_PASSWORD_LENGTH=8
REQUIRE_UPPERCASE=true
REQUIRE_LOWERCASE=true
REQUIRE_NUMBERS=true
REQUIRE_SPECIAL_CHARS=true
\`\`\`

### 🖥️ CLI Usage

The CLI provides comprehensive testing and management capabilities:

\`\`\`bash

# Start the interactive CLI

python -m auth.main

# Available commands:

# 1. Register User - Create new user account

# 2. Login User - Authenticate with email/password

# 3. Change Password - Update user password

# 4. Reset Password - Initiate password reset

# 5. Get OAuth URL - Generate social login URLs

# 6. Validate Token - Check JWT token validity

# 7. List Users - View all registered users

# 8. Delete User - Remove user account

# 9. Cleanup Tokens - Remove expired tokens

# 10. Setup OTP - Configure two-factor authentication

# 11. Verify OTP - Test OTP codes

# 12. Test OTP - Validate TOTP functionality

# 13. Generate Backup Codes - Create recovery codes

# 14. Disable OTP - Turn off two-factor auth

# 15. OTP Status - Check OTP configuration

\`\`\`

### 📡 API Usage

#### Start the FastAPI server:

\`\`\`bash
uvicorn auth.api.main:app --reload --port 8000
\`\`\`

#### Authentication Endpoints:

**Register User:**
\`\`\`bash
curl -X POST "http://localhost:8000/auth/register" \
 -H "Content-Type: application/json" \
 -d '{
"email": "user@example.com",
"password": "SecurePass123!",
"first_name": "John",
"last_name": "Doe"
}'
\`\`\`

**Login:**
\`\`\`bash
curl -X POST "http://localhost:8000/auth/login" \
 -H "Content-Type: application/json" \
 -d '{
"email": "user@example.com",
"password": "SecurePass123!",
"set_cookies": false
}'
\`\`\`

**Social Authentication:**
\`\`\`bash

# Get OAuth URL

curl "http://localhost:8000/social/auth/google?state=random_state"

# After OAuth callback, authenticate

curl -X POST "http://localhost:8000/social/auth" \
 -H "Content-Type: application/json" \
 -d '{
"provider": "google",
"auth_code": "authorization_code_from_callback",
"state": "random_state"
}'
\`\`\`

**OTP Setup:**
\`\`\`bash
curl -X POST "http://localhost:8000/otp/setup" \
 -H "Authorization: Bearer YOUR_JWT_TOKEN" \
 -H "Content-Type: application/json" \
 -d '{"password": "SecurePass123!"}'
\`\`\`

## 🔧 Programmatic Usage

### Basic Authentication Service

\`\`\`python
from auth.services.auth_service import AuthService
from auth.managers.user_manager import UserManager
from auth.managers.token_manager import TokenManager
from auth.repositories.user_repository import UserRepository
from auth.repositories.token_repository import TokenRepository
from auth.utils.security import SecurityUtils

# Initialize components with dependency injection

security_utils = SecurityUtils()
user_repository = UserRepository()
token_repository = TokenRepository()
user_manager = UserManager(user_repository)
token_manager = TokenManager(token_repository, security_utils)

# Initialize auth service

auth_service = AuthService(user_manager, token_manager, security_utils)

# Register a new user

try:
user = await auth.register_async({
"email": "user@example.com",
"password": "SecurePassword123!",
"first_name": "John",
"last_name": "Doe"
})
print(f"User registered: {user.email}")
except UserAlreadyExistsError:
print("User already exists")

# Authenticate user

try:
result = await auth.authenticate_async({
"email": "user@example.com",
"password": "SecurePassword123!"
})
print(f"Access Token: {result['access_token']}")
print(f"User: {result['user']['email']}")
except InvalidCredentialsError:
print("Invalid credentials")
\`\`\`

### Social Authentication

\`\`\`python
from auth.services.social_auth_service import SocialAuthService
from auth.providers.google import GoogleOAuthProvider
from auth.providers.azure import AzureOAuthProvider

# Initialize OAuth providers

google_provider = GoogleOAuthProvider()
azure_provider = AzureOAuthProvider() # Now uses MSAL

# Initialize social auth service

social_auth_service = SocialAuthService(
user_manager, token_manager, google_provider, azure_provider
)

# Get OAuth authorization URL

auth_url = social_auth.get_auth_url("google", state="csrf_token")
print(f"Redirect user to: {auth_url}")

# After user authorizes and returns with code

try:
result = await social_auth.authenticate_async({
"provider": "google",
"auth_code": "authorization_code_from_callback",
"state": "csrf_token"
})
print(f"User authenticated: {result['user']['email']}")
print(f"Is new user: {result['is_new_user']}")
except ProviderError as e:
print(f"OAuth error: {e}")
\`\`\`

### OTP/TOTP Implementation

\`\`\`python
from auth.services.otp_service import OTPService
from auth.managers.otp_manager import OTPManager
from auth.repositories.otp_repository import OTPRepository

# Initialize OTP components

otp_repository = OTPRepository()
otp_manager = OTPManager(otp_repository)
otp_service = OTPService(user_manager, otp_manager, security_utils)

# Setup OTP for user

try:
setup_result = await otp_service.setup_otp_async(user_id, "user_password")
print(f"OTP Secret: {setup_result['secret']}")
print(f"QR Code: {setup_result['qr_code']}") # Base64 encoded
print(f"Backup Codes: {setup_result['backup_codes']}")
except InvalidCredentialsError:
print("Invalid password")

# Verify OTP code

try:
is_valid = await otp_service.verify_otp_async(user_id, "123456")
if is_valid:
print("OTP verified successfully")
else:
print("Invalid OTP code")
except OTPError as e:
print(f"OTP error: {e}")
\`\`\`

## 🔒 Security Features

### Password Security

-   **bcrypt hashing** with configurable rounds (default: 12)
-   **Password policy enforcement**: length, complexity, character requirements
-   **Constant-time comparison** to prevent timing attacks
-   **Password history** (optional) to prevent reuse

### JWT Token Security

-   **RS256 signing** with RSA key pairs (recommended for production)
-   **Short-lived access tokens** (30 minutes default)
-   **Long-lived refresh tokens** (7 days default)
-   **Token revocation** with blacklist support
-   **Automatic token cleanup** for expired tokens

### OAuth Security

-   **CSRF protection** with state parameter validation
-   **PKCE support** for public clients (future enhancement)
-   **Secure redirect URI validation**
-   **ID token verification** for Azure MSAL integration

### OTP/TOTP Security

-   **RFC 6238 compliant** TOTP implementation
-   **30-second time windows** with clock skew tolerance
-   **Backup codes** with one-time use
-   **Rate limiting** on OTP attempts
-   **Secure secret generation** with cryptographically strong randomness

### General Security

-   **Input validation** with Pydantic models
-   **SQL injection prevention** through parameterized queries
-   **XSS protection** with proper output encoding
-   **HTTPS enforcement** in production
-   **Secure cookie settings** (HttpOnly, Secure, SameSite)

## 🏗️ Extending the Service

### Adding New OAuth Providers

1. **Create provider class:**
   \`\`\`python
   from auth.providers.base import BaseOAuthProvider

class GitHubOAuthProvider(BaseOAuthProvider):
def **init**(self):
self.client_id = config.GITHUB_CLIENT_ID
self.client_secret = config.GITHUB_CLIENT_SECRET
self.redirect_uri = config.GITHUB_REDIRECT_URI

    @property
    def provider_name(self) -> str:
        return "github"

    def get_auth_url(self, state: Optional[str] = None) -> str:
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": "user:email",
            "state": state
        }
        return f"https://github.com/login/oauth/authorize?{urlencode(params)}"

    def exchange_code(self, auth_code: str, state: Optional[str] = None) -> Dict[str, Any]:
        # Implementation for GitHub token exchange
        pass

    def get_user_info(self, access_token: str) -> Dict[str, Any]:
        # Implementation for GitHub user info
        pass

\`\`\`

2. **Register in social auth service:**
   \`\`\`python
   github_provider = GitHubOAuthProvider()
   social_auth_service = SocialAuthService(
   user_manager, token_manager,
   google_provider, azure_provider, github_provider
   )
   \`\`\`

### Custom Authentication Methods

\`\`\`python
from auth.services.base_auth_service import BaseAuthService

class APIKeyAuthService(BaseAuthService):
"""Custom authentication using API keys"""

    def authenticate(self, credentials: Dict[str, Any], set_cookies: bool = False):
        api_key = credentials.get("api_key")
        # Implement API key validation logic
        pass

    def register(self, user_data: Dict[str, Any]):
        # Implement API key generation for new users
        pass

\`\`\`

## 📊 Monitoring and Logging

### Health Checks

\`\`\`bash

# Check service health

curl http://localhost:8000/auth/health
curl http://localhost:8000/social/health
curl http://localhost:8000/otp/health
\`\`\`

### Metrics and Monitoring

-   **Authentication success/failure rates**
-   **Token generation and validation metrics**
-   **OAuth provider response times**
-   **OTP setup and verification rates**
-   **Database connection health**

### Logging Configuration

\`\`\`python
import logging

# Configure structured logging

logging.basicConfig(
level=logging.INFO,
format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Security event logging

security_logger = logging.getLogger('auth.security')
security_logger.info("User login attempt", extra={
"user_id": user.id,
"ip_address": request.client.host,
"user_agent": request.headers.get("user-agent")
})
\`\`\`

## 🚀 Production Deployment

### Environment Configuration

\`\`\`bash

# Production environment variables

JWT_SECRET=your-production-jwt-secret-256-bits-minimum
MONGODB_URL=mongodb://username:password@prod-mongo:27017/auth_service
COOKIE_SECURE=true
COOKIE_SAMESITE=strict
ENVIRONMENT=production

# OAuth Production URLs

GOOGLE_REDIRECT_URI=https://yourdomain.com/auth/google/callback
AZURE_REDIRECT_URI=https://yourdomain.com/auth/azure/callback
\`\`\`

### Docker Deployment

\`\`\`dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 8000

CMD ["uvicorn", "auth.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
\`\`\`

### Docker Compose

\`\`\`yaml
version: '3.8'
services:
auth-service:
build: .
ports: - "8000:8000"
environment: - MONGODB_URL=mongodb://mongo:27017/auth_service
depends_on: - mongo

mongo:
image: mongo:4.4
ports: - "27017:27017"
volumes: - mongo_data:/data/db

volumes:
mongo_data:
\`\`\`

### Kubernetes Deployment

\`\`\`yaml
apiVersion: apps/v1
kind: Deployment
metadata:
name: auth-service
spec:
replicas: 3
selector:
matchLabels:
app: auth-service
template:
metadata:
labels:
app: auth-service
spec:
containers: - name: auth-service
image: your-registry/auth-service:latest
ports: - containerPort: 8000
env: - name: MONGODB_URL
valueFrom:
secretKeyRef:
name: auth-secrets
key: mongodb-url - name: JWT_SECRET
valueFrom:
secretKeyRef:
name: auth-secrets
key: jwt-secret
\`\`\`

## 🧪 Testing

### Unit Tests

\`\`\`bash

# Run all tests

pytest

# Run with coverage

pytest --cov=auth_service --cov-report=html

# Run specific test categories

pytest tests/test_auth.py
pytest tests/test_oauth_providers.py
pytest tests/test_otp_service.py
\`\`\`

### Integration Tests

\`\`\`python
import pytest
from auth.services.auth_service import AuthService

@pytest.mark.asyncio
async def test_complete_auth_flow(): # Test registration -> login -> token validation
user = await auth.register_async({
"email": "test@example.com",
"password": "TestPass123!"
})

    result = await auth.authenticate_async({
        "email": "test@example.com",
        "password": "TestPass123!"
    })

    assert result["access_token"]
    assert result["user"]["email"] == "test@example.com"

\`\`\`

### Load Testing

\`\`\`bash

# Using locust for load testing

pip install locust

# Create locustfile.py for auth endpoints

locust -f tests/load_test.py --host=http://localhost:8000
\`\`\`

## 📚 API Documentation

### Authentication Endpoints

| Method | Endpoint                       | Description               | Auth Required |
| ------ | ------------------------------ | ------------------------- | ------------- |
| POST   | `/auth/register`               | Register new user         | No            |
| POST   | `/auth/login`                  | Login with email/password | No            |
| POST   | `/auth/logout`                 | Logout current user       | Yes           |
| POST   | `/auth/logout-all`             | Logout from all devices   | Yes           |
| POST   | `/auth/change-password`        | Change user password      | Yes           |
| POST   | `/auth/reset-password`         | Initiate password reset   | No            |
| POST   | `/auth/reset-password/confirm` | Confirm password reset    | No            |
| GET    | `/auth/health`                 | Service health check      | No            |

### Social Authentication Endpoints

| Method | Endpoint                  | Description          | Auth Required |
| ------ | ------------------------- | -------------------- | ------------- |
| GET    | `/social/auth/{provider}` | Get OAuth URL        | No            |
| POST   | `/social/auth`            | Complete OAuth flow  | No            |
| GET    | `/social/health`          | Service health check | No            |

### OTP Endpoints

| Method | Endpoint                   | Description          | Auth Required |
| ------ | -------------------------- | -------------------- | ------------- |
| POST   | `/otp/setup`               | Setup TOTP for user  | Yes           |
| POST   | `/otp/verify`              | Verify OTP code      | Yes           |
| POST   | `/otp/disable`             | Disable OTP for user | Yes           |
| GET    | `/otp/backup-codes`        | Get backup codes     | Yes           |
| POST   | `/otp/backup-codes/verify` | Verify backup code   | Yes           |
| GET    | `/otp/status`              | Get OTP status       | Yes           |
| GET    | `/otp/health`              | Service health check | No            |

## 🔧 Configuration Reference

### Complete Environment Variables

\`\`\`bash

# Database Configuration

MONGODB_URL=mongodb://localhost:27017/auth_service
MONGODB_DATABASE=auth_service

# JWT Configuration

JWT_SECRET=your-super-secret-jwt-key-256-bits-minimum
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

# Cookie Configuration

COOKIE_SECURE=false # true in production
COOKIE_SAMESITE=lax # strict in production
COOKIE_DOMAIN=localhost
COOKIE_PATH=/

# Google OAuth

GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:8000/auth/google/callback

# Azure OAuth (MSAL)

AZURE_CLIENT_ID=your-azure-client-id
AZURE_CLIENT_SECRET=your-azure-client-secret
AZURE_TENANT_ID=your-azure-tenant-id
AZURE_REDIRECT_URI=http://localhost:8000/auth/azure/callback

# Password Policy

MIN_PASSWORD_LENGTH=8
REQUIRE_UPPERCASE=true
REQUIRE_LOWERCASE=true
REQUIRE_NUMBERS=true
REQUIRE_SPECIAL_CHARS=true
MAX_PASSWORD_LENGTH=128

# Security Settings

BCRYPT_ROUNDS=12
TOKEN_CLEANUP_INTERVAL_HOURS=24
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION_MINUTES=30

# OTP Configuration

OTP_ISSUER=YourApp
OTP_WINDOW=1 # Allow 1 time step before/after current
BACKUP_CODES_COUNT=10

# Rate Limiting

RATE_LIMIT_ENABLED=true
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=3600 # 1 hour

# Logging

LOG_LEVEL=INFO
LOG_FORMAT=json
SECURITY_LOG_ENABLED=true
\`\`\`

## 🤝 Contributing

### Development Setup

\`\`\`bash

# Clone repository

git clone <repository-url>
cd auth-service

# Create virtual environment

python -m venv venv
source venv/bin/activate # On Windows: venv\Scripts\activate

# Install development dependencies

pip install -r requirements-dev.txt

# Install pre-commit hooks

pre-commit install

# Run tests

pytest
\`\`\`

### Code Style

-   **Black** for code formatting
-   **isort** for import sorting
-   **flake8** for linting
-   **mypy** for type checking

### Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Update documentation
7. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support and Troubleshooting

### Common Issues

**MongoDB Connection Issues:**
\`\`\`bash

# Check MongoDB is running

mongosh --eval "db.adminCommand('ismaster')"

# Check connection string format

MONGODB_URL=mongodb://username:password@host:port/database
\`\`\`

**JWT Token Issues:**
\`\`\`bash

# Verify JWT secret is set and sufficiently long (256 bits minimum)

echo $JWT_SECRET | wc -c # Should be > 32 characters
\`\`\`

**OAuth Provider Issues:**

-   Verify redirect URIs match exactly in provider console
-   Check client ID and secret are correct
-   Ensure proper scopes are requested

### Getting Help

-   📖 Check this documentation first
-   🐛 Create an issue on GitHub for bugs
-   💡 Start a discussion for feature requests
-   📧 Contact maintainers for security issues

### Roadmap

-   [ ] **Enhanced OTP Support**: SMS, Email OTP options
-   [ ] **Additional OAuth Providers**: Apple, GitHub, Microsoft
-   [ ] **Advanced Security**: Device fingerprinting, risk scoring
-   [ ] **Session Management**: Advanced session controls
-   [ ] **Audit Logging**: Comprehensive security event logging
-   [ ] **Rate Limiting**: Built-in rate limiting middleware
-   [ ] **Multi-tenancy**: Support for multiple organizations
-   [ ] **API Keys**: Alternative authentication method
-   [ ] **Webhooks**: Event notifications for auth events
-   [ ] **Admin Dashboard**: Web interface for user management

---

**Built with ❤️ using Python, FastAPI, MongoDB, and modern security practices.**
