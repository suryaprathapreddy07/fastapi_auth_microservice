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
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


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
            raise e

    async def login(self, email: str, password: str):
        try:
            db_auth_user = await self._find_user_by_email(email)
            if db_auth_user is None or not self._verify_password(password, db_auth_user.password):
                raise HTTPException(
                    status_code=401,
                    detail="Incorrect email or password",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            userData = {'name': db_auth_user.name, 'email': db_auth_user.email,
                        'address': db_auth_user.address, 'phone': db_auth_user.phone, 'role': db_auth_user.role}
            access_token = self._create_access_token(data={"data": userData})
            return {"access_token": access_token, "token_type": "bearer"}
        except Exception as e:
            raise e

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

    async def send_otp_to_user(self, phone: str, otp: str):
        # replace with otp sending logic
        print('otp sent successfully')
        pass

    def _verify_otp(self, plain_otp, stored_hashed_otp):
        hashed_otp = hashlib.sha256(plain_otp.encode()).hexdigest()
        return hashed_otp == stored_hashed_otp

    async def mobile_login(self, phone: str):
        try:
            db_auth_user = await self.find_user_by_phone(phone)
            if db_auth_user is None:
                raise HTTPException(
                    status_code=404,
                    detail="User not found",
                )
            otp = str(random.randint(100000, 999999))
            hashed_otp = hashlib.sha256(otp.encode()).hexdigest()
            db_auth_user.otp = hashed_otp
            await self.session.commit()
            self.send_otp_to_user(phone, otp)
            # Till sms service is implemented we can send otp here for testing
            return {"message": "OTP sent successfully", "otp": otp}
        except Exception as e:
            raise e

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
            userData = {'name': db_auth_user.name, 'email': db_auth_user.email,
                        'address': db_auth_user.address, 'phone': db_auth_user.phone, 'role': db_auth_user.role}
            access_token = self._create_access_token(data={"data": userData})
            return {"access_token": access_token, "token_type": "bearer"}
        except Exception as e:
            print(e)
            raise e

    # forgot password
    async def generate_reset_token(self, email: str) -> str:
        try:
            user = await self._find_user_by_email(email)
            if user is None:
                raise EntityDoesNotExist("User not found")
            reset_token = jwt.encode(
                {"sub": user.email}, SECRET_KEY, algorithm=ALGORITHM)
            user.reset_token = reset_token.decode("utf-8")
            await self.session.commit()
            return reset_token
        except EntityDoesNotExist:
            raise HTTPException(status_code=404, detail="User not found")
        except Exception as e:
            raise e

    async def send_password_reset_email(self, email: str, reset_token: str):
        try:
            # replace the values with actual email configuration
            sender_email = "test@test.com"
            sender_password = "testAppPassword"
            app_domain = "your-app.com"
            subject = "Password Reset"
            body = f"Click on the link to reset your password: https://{app_domain}/reset-password?token={reset_token}"

            msg = MIMEMultipart()
            msg.attach(MIMEText(body, 'plain'))
            msg['From'] = sender_email
            msg['To'] = email
            msg['Subject'] = subject

            with smtplib.SMTP('smtp.gmail.com', 587) as server:
                server.starttls()
                server.login(sender_email, sender_password)
                server.sendmail(sender_email, email, msg.as_string())

            print(f"Password reset email sent to {email}")

        except Exception as e:
            print(f"Error sending password reset email to {email}: {e}")

    async def forgot_password(self, email: str):
        try:
            reset_token = await self.generate_reset_token(email)
            await self.send_password_reset_email(email, reset_token)
            return {"message": "Password reset link sent to your email"}

        except EntityDoesNotExist:
            raise HTTPException(status_code=404, detail="User not found")
        except HTTPException as he:
            raise he
        except Exception as e:
            raise e

    async def reset_password(self, token: str, new_password: str):
        try:
            email = jwt.decode(token, SECRET_KEY,
                               algorithms=[ALGORITHM])["sub"]
            user = await self._find_user_by_email(email)

            if user is None:
                raise EntityDoesNotExist("User not found")

            hashed_password = self._hash_password(new_password)
            user.password = hashed_password
            user.reset_token = None
            await self.session.commit()

            return {"message": "Password reset successfully"}

        except EntityDoesNotExist:
            raise HTTPException(status_code=404, detail="User not found")
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=400, detail="Reset token has expired")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=400, detail="Invalid reset token")
        except Exception as e:
            raise e
