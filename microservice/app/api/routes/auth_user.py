from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status,Form
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import EmailStr

from app.api.dependencies.repositories import get_repository
from app.db.errors import EntityDoesNotExist
from app.db.repositories.auth_user import AuthUserRepository
from app.schemas.auth_user import AuthUserCreate, AuthUserPatch, AuthUserRead
router = APIRouter()


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

@router.post(
    "/login",
    response_model=dict,  # Adjust this to match your expected response model
    status_code=status.HTTP_200_OK,
    name="user login",
    tags=["Authentication"]
)
async def login(
    form_data: CustomOAuth2PasswordRequestForm = Depends(),  # You can use OAuth2PasswordBearer for a token-based approach
    repository: AuthUserRepository = Depends(get_repository(AuthUserRepository)),
) -> dict:
    try:
        # Attempt to log in with the provided credentials
        login_result = await repository.login(form_data.username, form_data.password)
    except HTTPException as e:
        raise e
    return login_result
# @router.get(
#     "/auth_user",
#     response_model=list[Optional[AuthUserRead]],
#     status_code=status.HTTP_200_OK,
#     name="get_auth_users",
# )
# async def get_auth_user(
#     limit: int = Query(default=10, lte=100),
#     offset: int = Query(default=0),
#     repository: AuthUserRepository = Depends(get_repository(AuthUserRepository)),
# ) -> list[Optional[AuthUserRead]]:
#     return await repository.list(limit=limit, offset=offset)


