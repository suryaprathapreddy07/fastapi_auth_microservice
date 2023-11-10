from uuid import UUID

from app.db.tables.auth_user import AuthUserBase


class AuthUserCreate(AuthUserBase):
    ...


class AuthUserRead(AuthUserBase):
    id: UUID


class AuthUserPatch(AuthUserBase):
    ...

from pydantic import BaseModel

class AuthCredentials(BaseModel):
    email: str
    password: str

class MobileLoginCredentials(BaseModel):
    phone: str

class MobileLoginVerifyCredentials(BaseModel):
    phone: str
    otp:str



