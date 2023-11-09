from typing import Optional
from uuid import UUID
from passlib.hash import bcrypt
from fastapi.security import OAuth2PasswordRequestForm
from fastapi import HTTPException
from datetime import datetime, timedelta
import jwt
from app.db.errors import EmailAlreadyExistsError
from dotenv import load_dotenv
import os
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession
from app.db.errors import EntityDoesNotExist
from app.db.tables.base_class import StatusEnum
from app.db.tables.auth_user import AuthUser
from app.schemas.auth_user import AuthUserCreate, AuthUserPatch, AuthUserRead
from app.core.config import settings


SECRET_KEY = settings.jwt_secret_key
ALGORITHM = settings.ALGORITHM
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class AuthUserRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    def _hash_password(self, password: str) -> str:
        return bcrypt.hash(password)

    async def _get_instance(self, auth_user_id: UUID):
        statement = (
            select(AuthUser)
            .where(AuthUser.id == auth_user_id)
            .where(AuthUser.status != StatusEnum.deleted)
        )
        results = await self.session.exec(statement)
        return results.first()

    async def create(self, auth_user_create: AuthUserCreate) -> AuthUserRead:
        try:
            # Check if the email already exists in the database
            if await self._email_exists(auth_user_create.email):
                raise EmailAlreadyExistsError
            # Hash the user's password before storing it
            hashed_password = self._hash_password(auth_user_create.password)
            auth_user_create.password = hashed_password
            db_auth_user = AuthUser.from_orm(auth_user_create)
            self.session.add(db_auth_user)
            await self.session.commit()
            await self.session.refresh(db_auth_user)
            return AuthUserRead(**db_auth_user.dict())
        except Exception as e:
            # Handle exceptions and provide appropriate error messages or response codes
            raise HTTPException(status_code=400, detail="Error creating user")

    async def login(self, email: str, password: str):
        try:
            # Find the user by email
            db_auth_user = await self._find_user_by_email(email)
            if db_auth_user is None or not self._verify_password(password, db_auth_user.password):
                raise HTTPException(
                    status_code=401,
                    detail="Incorrect email or password",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            # Generate a JWT token for the authenticated user
            access_token = self._create_access_token(data={"sub": db_auth_user.email})
            return {"access_token": access_token, "token_type": "bearer"}
        except Exception as e:
            print(e)
            # Handle exceptions and provide appropriate error messages or response codes
            raise HTTPException(status_code=400, detail="Error during login")

    async def _find_user_by_email(self, email: str):
        statement = (
            select(AuthUser)
            .where(AuthUser.email == email)
            .where(AuthUser.status != StatusEnum.deleted)
        )
        results = await self.session.exec(statement)
        return results.first()

    def _verify_password(self, plain_password, hashed_password):
        return bcrypt.verify(plain_password, hashed_password)

    def _create_access_token(self, data: dict):
        to_encode = data.copy()
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        expire = datetime.utcnow() + access_token_expires
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt

    async def _email_exists(self, email: str):
        statement = select(AuthUser).where(AuthUser.email == email)
        results = await self.session.exec(statement)
        return bool(results.first())
