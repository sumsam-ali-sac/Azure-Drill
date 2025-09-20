"""
FastAPI application for authentication service.
"""

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from contextlib import asynccontextmanager
from auth_service.api.routes import auth, social, otp
from auth_service.api.dependencies import get_current_user
from auth_service.config import config
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    logger.info("Starting authentication service...")
    yield
    logger.info("Shutting down authentication service...")

# Create FastAPI application
app = FastAPI(
    title="Authentication Service API",
    description="Comprehensive authentication service with email/password, social login, and OTP support",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security scheme
security = HTTPBearer()

# Include routers
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(social.router, prefix="/api/social", tags=["Social Authentication"])
app.include_router(otp.router, prefix="/api/otp", tags=["OTP Authentication"])

@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "Authentication Service API",
        "version": "1.0.0",
        "docs": "/docs"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "authentication-service"
    }

@app.get("/api/me")
async def get_current_user_info(current_user = Depends(get_current_user)):
    """Get current authenticated user information."""
    return {
        "user": current_user,
        "authenticated": True
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "auth_service.api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
