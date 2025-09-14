from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, Request, Response, HTTPException
from fastapi.responses import JSONResponse, RedirectResponse

from root.auth.common.exceptions import (
    EmailAlreadyExistsError,
    InvalidCredentialsError,
    TokenExpiredError,
    WeakPasswordError,
)
from root.auth.common.middleware import (
    AuthUser,
    create_auth_response,
    get_current_user,
    get_current_user_optional,
)
from root.auth.common.schemas import (
    APIResponse,
    TokenRefresh,
    UserLogin,
    UserRegistration,
)
from root.auth.core import auth_manager


auth_router = APIRouter(prefix="/auth", tags=["Authentication"])


@auth_router.post("/register", response_model=APIResponse)
async def register(
    registration_data: UserRegistration, response: Response
) -> Dict[str, Any]:
    try:
        result = auth_manager.register_user(registration_data)
        return {
            "success": True,
            "message": result["message"],
            "data": {
                "user": result["user"].dict(),
                "requires_verification": result["requires_verification"],
            },
        }
    except (EmailAlreadyExistsError, WeakPasswordError) as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)


@auth_router.post("/login", response_model=APIResponse)
async def login(
    login_data: UserLogin, request: Request, response: Response
) -> Dict[str, Any]:
    try:
        result = auth_manager.login_with_password(login_data, request)
        tokens = result["tokens"]
        user_data = result["user"].dict()
        return create_auth_response(
            tokens.access_token,
            tokens.refresh_token,
            user_data,
            response,
            result["message"],
        )
    except (InvalidCredentialsError, TokenExpiredError) as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)


@auth_router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    current_user: Optional[AuthUser] = Depends(get_current_user_optional),
) -> Dict[str, Any]:
    result = auth_manager.logout_user(request, response)
    return result


@auth_router.post("/refresh", response_model=APIResponse)
async def refresh_token(token_data: TokenRefresh, response: Response) -> Dict[str, Any]:
    try:
        result = auth_manager.refresh_token(token_data.refresh_token)
        return result
    except TokenExpiredError as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)


@auth_router.get("/me")
async def get_current_user_profile(
    current_user: AuthUser = Depends(get_current_user),
) -> Dict[str, Any]:
    return {"success": True, "data": {"user": current_user.to_dict()}}
