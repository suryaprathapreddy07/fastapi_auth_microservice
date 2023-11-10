from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status,Form
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import EmailStr
from fastapi.security import OAuth2PasswordBearer

from app.api.dependencies.repositories import get_repository
from app.db.errors import EntityDoesNotExist
from app.db.repositories.auth_user import AuthUserRepository
from app.schemas.auth_user import AuthUserCreate, AuthUserPatch, AuthUserRead,AuthCredentials,MobileLoginCredentials,MobileLoginVerifyCredentials
from app.db.security import get_current_user
router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class CustomOAuth2PasswordRequestForm(OAuth2PasswordRequestForm):
    email: EmailStr = Form(..., description="User's email")

@router.post(
    "/signup",
    response_model=AuthUserRead,
    status_code=status.HTTP_201_CREATED,
    name="create user",
    tags=["Authentication"]
)
async def create_auth_user(
    auth_user_create: AuthUserCreate = Body(...),
    repository: AuthUserRepository = Depends(get_repository(AuthUserRepository)),
) -> AuthUserRead:
    return await repository.create(auth_user_create=auth_user_create)

# email login
@router.post(
    "/login",
    response_model=dict,  # Adjust this to match your expected response model
    status_code=status.HTTP_200_OK,
    name="user login",
    tags=["Authentication"]
)
async def login(
    credentials: AuthCredentials = Body(...),  # You can use OAuth2PasswordBearer for a token-based approach
    repository: AuthUserRepository = Depends(get_repository(AuthUserRepository)),
) -> dict:
    try:
        # Attempt to log in with the provided credentials
        login_result = await repository.login(credentials.email, credentials.password)
    except HTTPException as e:
        raise e
    return login_result

# mobile login
@router.post(
    "/login/mobile",
    response_model=dict,  # Adjust this to match your expected response model
    status_code=status.HTTP_200_OK,
    name="Mobile login",
    tags=["Authentication"]
)
async def loginMobile(
    credentials: MobileLoginCredentials = Body(...),  # You can use OAuth2PasswordBearer for a token-based approach
    repository: AuthUserRepository = Depends(get_repository(AuthUserRepository)),
) -> dict:
    try:
        # Attempt to log in with the provided credentials
        login_result = await repository.mobile_login(credentials.phone)
    except HTTPException as e:
        raise e
    return login_result

# Verify mobile login
@router.post(
    "/login/mobile/verify",
    response_model=dict,  # Adjust this to match your expected response model
    status_code=status.HTTP_200_OK,
    name="Verify Mobile login",
    tags=["Authentication"]
)
async def verifyMobileLogin(
    credentials: MobileLoginVerifyCredentials = Body(...),  # You can use OAuth2PasswordBearer for a token-based approach
    repository: AuthUserRepository = Depends(get_repository(AuthUserRepository)),
) -> dict:
    try:
        # Attempt to log in with the provided credentials
        login_result = await repository.mobile_login_verify_otp(credentials.phone,credentials.otp)
    except HTTPException as e:
        raise e
    return login_result

@router.get("/user",tags=["Authentication"],name="get user",)
async def get_private_data(current_user: dict = Depends(get_current_user)):
    return {"message": "You have access to this private data", "user": current_user}

