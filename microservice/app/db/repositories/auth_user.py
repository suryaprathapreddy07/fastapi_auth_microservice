from typing import Optional
from uuid import UUID
from passlib.hash import bcrypt
import random
import hashlib
from fastapi.security import OAuth2PasswordRequestForm
from fastapi import HTTPException, Depends
from datetime import datetime, timedelta
import jwt
from jwt import PyJWTError
from fastapi.security import OAuth2PasswordBearer
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


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


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
            if await self._email_exists(auth_user_create.email):
                raise EmailAlreadyExistsError
            hashed_password = self._hash_password(auth_user_create.password)
            auth_user_create.password = hashed_password
            db_auth_user = AuthUser.from_orm(auth_user_create)
            self.session.add(db_auth_user)
            await self.session.commit()
            await self.session.refresh(db_auth_user)
            return AuthUserRead(**db_auth_user.dict())
        except Exception as e:
            raise HTTPException(status_code=400, detail="Error creating user")

    async def login(self, email: str, password: str):
        try:
            db_auth_user = await self._find_user_by_email(email)
            if db_auth_user is None or not self._verify_password(password, db_auth_user.password):
                raise HTTPException(
                    status_code=401,
                    detail="Incorrect email or password",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            userData={'name': db_auth_user.name,'email': db_auth_user.email,'address': db_auth_user.address,'phone': db_auth_user.phone,'role': db_auth_user.role}
            access_token = self._create_access_token(data={"data": userData})
            return {"access_token": access_token, "token_type": "bearer"}
        except Exception as e:
            print(e)
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
    def decode_jwt_token(token: str):
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            return payload
        except PyJWTError:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
    # Mobile Authentication
    async def find_user_by_phone(self, phone: str):
        statement = (
            select(AuthUser)
            .where(AuthUser.phone == phone)
            .where(AuthUser.status != StatusEnum.deleted)
        )
        results = await self.session.exec(statement)
        return results.first()
    
    async def send_otp_to_user(self,phone: str, otp: str):
        print('otp sent successfully')
        pass

    def _verify_otp(self, plain_otp, stored_hashed_otp):
        
        hashed_otp = hashlib.sha256(plain_otp.encode()).hexdigest()
        return hashed_otp == stored_hashed_otp
    
    async def mobile_login(self, phone: str):
        try:
           
            db_auth_user = await self.find_user_by_phone(phone)
            print(db_auth_user)
            if db_auth_user is None:
                raise HTTPException(
                    status_code=404,
                    detail="User not found",
                )

            
            otp = str(random.randint(100000, 999999))

            
            hashed_otp = hashlib.sha256(otp.encode()).hexdigest()
            db_auth_user.otp = hashed_otp
            await self.session.commit()

            
            self.send_otp_to_user(phone,otp)

            # Till sms service is implemented we can send otp here for testing
            return {"message": "OTP sent successfully","otp":otp}
        except Exception as e:
            raise HTTPException(status_code=400, detail="Error during OTP request")

    async def mobile_login_verify_otp(self, phone: str, otp: str):
        try:
            
            db_auth_user = await self.find_user_by_phone(phone)
            if db_auth_user is None or not self._verify_otp(otp, db_auth_user.otp):
                raise HTTPException(
                    status_code=401,
                    detail="Incorrect phone number or OTP",
                    headers={"WWW-Authenticate": "Bearer"},
                )

           
            db_auth_user.otp = None
            await self.session.commit()

            userData = {'name': db_auth_user.name, 'email': db_auth_user.email, 'address': db_auth_user.address, 'phone': db_auth_user.phone, 'role': db_auth_user.role}
            access_token = self._create_access_token(data={"data": userData})
            return {"access_token": access_token, "token_type": "bearer"}
        except Exception as e:
            print(e)
            raise HTTPException(status_code=400, detail="Error during OTP verification")

    


